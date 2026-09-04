
from pyspark.sql import functions as F
from delta.tables import DeltaTable

# Auto Loader's checkpoint tracks file consumption independently of what's
# in the Bronze Delta table -- once a PDF has passed through a completed
# streaming micro-batch, the streaming source will never hand it back,
# no matter what happens to its row afterward. So retrying Bronze needs
# this separate batch path: it reads eligible statements' source_path
# straight from Bronze itself and does a plain binaryFile batch read of
# just those specific files.

candidates = spark.table(TBL_BRONZE_EXTRACTION).select("statement_hash", "source_path")
eligible = get_eligible_statements("pdf_extraction", candidates)

paths_to_reprocess = [r["source_path"] for r in eligible.select("source_path").distinct().collect()]

# if not paths_to_reprocess:
#     print("Bronze backfill: nothing eligible for re-extraction.")
# else:
#     print(f"Bronze backfill: re-extracting {len(paths_to_reprocess)} file(s).")

#     raw_batch_df = spark.read.format("binaryFile").load(paths_to_reprocess)


if not paths_to_reprocess:
    print("Bronze backfill: nothing eligible for re-extraction.")
else:
    # Not every historical statement's source file is guaranteed to still
    # exist in the Volume (old test uploads, manual cleanup, etc). A
    # single missing path fails the entire binaryFile batch load, so check
    # existence first and handle the two groups separately instead of
    # letting one stale reference block everyone else's legitimate backfill.
    existing_paths, missing_paths = [], []
    for p in paths_to_reprocess:
        try:
            dbutils.fs.ls(p)
            existing_paths.append(p)
        except Exception:
            missing_paths.append(p)

    if missing_paths:
        print(f"Bronze backfill: {len(missing_paths)} source file(s) no longer exist, marking FAILED: {missing_paths}")
        missing_log_rows = (
            eligible.filter(F.col("source_path").isin(missing_paths))
            .select("statement_hash", "source_path")
            .distinct()
            .withColumn("status", F.lit("FAILED"))
            .withColumn("duration_sec", F.lit(0.0))
            .withColumn("error", F.lit("Source file no longer exists in Volume"))
        )
        log_pipeline_stage(spark, "pdf_extraction", missing_log_rows)

    if not existing_paths:
        print("Bronze backfill: no existing files left to re-extract.")
    else:
        print(f"Bronze backfill: re-extracting {len(existing_paths)} file(s).")

        raw_batch_df = spark.read.format("binaryFile").load(existing_paths)


    extracted_df = (
        raw_batch_df.select("path", "content")
        .mapInPandas(extract_pdfs, schema=EXTRACTION_SCHEMA)
        .dropDuplicates(['statement_hash'])
        .withColumn("ingested_at", F.current_timestamp())
        .withColumn("pipeline_stages", F.lit("bronze_backfill"))
    )

    # materialize once via staging (serverless has no .cache()/.persist())
    extracted_df.write.format("delta").mode("overwrite").option("overwriteSchema", "true").saveAsTable(TBL_BRONZE_STAGING)
    staged_df = spark.table(TBL_BRONZE_STAGING)
    row_count = staged_df.count()

    # unlike the streaming path, these statement_hashes usually already
    # exist in Bronze (that's the whole point of a backfill) -- so this
    # merge needs an update branch, not just insert-only
    target_table = DeltaTable.forName(spark, TBL_BRONZE_EXTRACTION)
    update_cols = {c: f"source.{c}" for c in staged_df.columns if c != "statement_hash"}
    insert_cols = {c: f"source.{c}" for c in staged_df.columns}
    (
        target_table.alias("target")
        .merge(staged_df.alias("source"), "target.statement_hash = source.statement_hash")
        .whenMatchedUpdate(set=update_cols)
        .whenNotMatchedInsert(values=insert_cols)
        .execute()
    )

    log_rows = staged_df.select(
        F.col("statement_hash"),
        F.col("source_path"),
        F.when(F.col("extraction_error").isNull(), F.lit("SUCCESS")).otherwise(F.lit("FAILED")).alias("status"),
        F.col("extraction_duration_sec").alias("duration_sec"),
        F.col("extraction_error").alias("error"),
    )
    log_pipeline_stage(spark, "pdf_extraction", log_rows)

    # this stage genuinely rewrote Bronze data for these statements --
    # classification's old output for them is now stale
    invalidate_downstream("pdf_extraction", staged_df.select("statement_hash"))

    print(f"Bronze backfill re-extracted {row_count} statement(s) in {TBL_BRONZE_EXTRACTION}")
