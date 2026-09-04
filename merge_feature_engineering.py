$run ./00_config;

# IMPORTING THE LIBRARIES
from pyspark.sql import functions as F
import pandas as pd
import time
from delta.tables import DeltaTable
from pyspark.sql.types import StructType,StructField,StringType,DoubleType


OPENING_BALANCE_SCHEMA = StructType([
    StructField('statement_hash',StringType()),
    StructField('opening_balance',DoubleType()),
])
# def compute_opening_balance_partition(iterator):
#     for batch in iterator:
#         results = []
#         for statement_hash,group in batch.groupby('statement_hash'):
#             group = group.sort_values('line_no')
#             first_row,last_row = group.iloc[0],group.iloc[-1]

#             first_date = _parse_date_loose(first_row['txn_date_raw'])
#             last_date = _parse_date_loose(last_row['txn_date_raw'])

#             if first_date and last_date and last_date < first_date:
#                 first_row = group.iloc[-1]

#             bal = first_row['running_balance']
#             debit = 0.0 if pd.isna(first_row['debit_amount']) else first_row['debit_amount']
#             credit = 0.0 if pd.isna(first_row['credit_amount']) else first_row['credit_amount']

#             opening_balance = None if pd.isna(bal) else bal - debit + credit
#             results.append({'statement_hash':statement_hash,'opening_balance':opening_balance})
#         yield pd.DataFrame(results,columns=['statement_hash','opening_balance'])


from pyspark.sql.window import Window
from collections import defaultdict


# CREATING THE FINAL GOLD TABLE
spark.sql(f"""
        CREATE TABLE IF NOT EXISTS {TBL_GOLD_ACCOUNT_FEATURES} (
        statement_hash string,
        bank_format string,
        total_transactions long,
        total_inflow double,
        total_outflow double,
        avg_transaction_amount double,
        min_balance double,
        max_balance double,
        avg_balance double,
        salary_credit_count long,
        atm_withdrawl_count long,
        upi_txn_count long,
        bounce_or_reversal_count long,
        emi_txn_count long,
        distinct_txn_types long,
        opening_balance double,
        closing_balance DOUBLE,
        computed_at Timestamp) using delta
        """)

ensure_table_columns(TBL_GOLD_ACCOUNT_FEATURES, {
    "statement_hash": "STRING", "bank_format": "STRING", "total_transactions": "LONG",
    "total_inflow": "DOUBLE", "total_outflow": "DOUBLE", "avg_transaction_amount": "DOUBLE",
    "min_balance": "DOUBLE", "max_balance": "DOUBLE", "avg_balance": "DOUBLE",
    "salary_credit_count": "LONG", "atm_withdrawl_count": "LONG", "upi_txn_count": "LONG",
    "bounce_or_reversal_count": "LONG", "emi_txn_count": "LONG", "distinct_txn_types": "LONG",
    "opening_balance":'DOUBLE',"closing_balance":"DOUBLE",
    "computed_at": "TIMESTAMP",
})

# ONLY STATEMENTS THAT PASSED VALIDATION (business-logic gate) ...
validated_ok = (
    spark.table(TBL_SILVER_VALIDATED)
    .filter(F.col('validation_status').isin('PASSED', "PARTIAL"))
    .select('statement_hash')
)

# ... AND are eligible per the retry/version policy for the merge stage
# itself (this replaces the old already_in_gold left-anti check -- it now
# also picks up FAILED-under-cap retries and statements whose logged merge
# logic_version is older than STAGE_LOGIC_VERSIONS['merge'])
new_eligible = get_eligible_statements("merge", validated_ok)

txns = (
    spark.table(TBL_SILVER_TRANSACTIONS)
    .join(new_eligible,on='statement_hash',how='inner')
)

t0 = time.time()
try:
    features_df = (
        txns.groupBy("statement_hash", "bank_format")
        .agg(
            F.count("*").alias("total_transactions"),
            F.sum("credit_amount").alias("total_inflow"),
            F.sum("debit_amount").alias("total_outflow"),
            F.avg(F.coalesce("debit_amount", "credit_amount")).alias("avg_transaction_amount"),
            F.min("running_balance").alias("min_balance"),
            F.max("running_balance").alias("max_balance"),
            F.avg("running_balance").alias("avg_balance"),
            F.sum(F.when(F.col("txn_type") == "SALARY_CREDIT", 1).otherwise(0)).alias("salary_credit_count"),
            F.sum(F.when(F.col("txn_type") == "ATM_WITHDRAWL", 1).otherwise(0)).alias("atm_withdrawl_count"),
            F.sum(F.when(F.col("txn_type") == "UPI", 1).otherwise(0)).alias("upi_txn_count"),
            F.sum(F.when(F.col("txn_type") == "REVERSAL", 1).otherwise(0)).alias("bounce_or_reversal_count"),
            F.sum(F.when(F.col("txn_type") == "EMI", 1).otherwise(0)).alias("emi_txn_count"),
            F.countDistinct("txn_type").alias("distinct_txn_types"),
        )
        .withColumn("computed_at", F.current_timestamp())
    )

    # opening_balance_df = (
    #     txns.select('statement_hash','line_no','txn_date_raw','running_balance','debit_amount','credit_amount')
    #     .repartition('statement_hash')
    #     .mapInPandas(compute_opening_balance_partition,schema=OPENING_BALANCE_SCHEMA)
    # )
    edge_rows = (
    txns
    .withColumn("rn_asc", F.row_number().over(Window.partitionBy("statement_hash").orderBy(F.col("line_no").asc())))
    .withColumn("rn_desc", F.row_number().over(Window.partitionBy("statement_hash").orderBy(F.col("line_no").desc())))
    .filter((F.col("rn_asc") == 1) | (F.col("rn_desc") == 1))
    .select("statement_hash", "rn_asc", "rn_desc", "txn_date_raw", "debit_amount", "credit_amount", "running_balance")
    .collect()
    )

    by_stmt = defaultdict(dict)
    for r in edge_rows:
        if r["rn_asc"] == 1:
            by_stmt[r["statement_hash"]]["first"] = r
        if r["rn_desc"] == 1:
            by_stmt[r["statement_hash"]]["last"] = r

    opening_rows = []
    for stmt_hash, edges in by_stmt.items():
        first_row, last_row = edges.get("first"), edges.get("last")
        if first_row is None:
            continue

        first_date = _parse_date_loose(first_row["txn_date_raw"])
        last_date = _parse_date_loose(last_row["txn_date_raw"]) if last_row else None
        chosen = last_row if (first_date and last_date and last_date < first_date) else first_row

        bal = chosen["running_balance"]
        debit = chosen["debit_amount"] or 0.0
        credit = chosen["credit_amount"] or 0.0
        opening_balance = None if bal is None else bal - credit + debit
        opening_rows.append((stmt_hash, opening_balance))

    opening_balance_df = spark.createDataFrame(opening_rows, schema=OPENING_BALANCE_SCHEMA)

    features_df = (
        features_df
        .join(opening_balance_df,on='statement_hash',how='left')
        .withColumn('closing_balance', F.col('opening_balance') + F.col('total_inflow') - F.col('total_outflow') )
    )

    # materialize once via staging (serverless has no .cache()/.persist())
    features_df.write.format("delta").mode("overwrite").option("overwriteSchema", "true").saveAsTable(TBL_GOLD_STAGING)
    staged_features_df = spark.table(TBL_GOLD_STAGING)
    row_count = staged_features_df.count()
    duration = round(time.time() - t0, 3)

    # a statement can now be RE-merged (not just newly merged), so this
    # needs an update branch alongside insert, not insert-only
    target_table = DeltaTable.forName(spark, TBL_GOLD_ACCOUNT_FEATURES)
    update_cols = {c: f"source.{c}" for c in staged_features_df.columns if c != "statement_hash"}
    insert_cols = {c: f"source.{c}" for c in staged_features_df.columns}
    (
        target_table.alias("target")
        .merge(staged_features_df.alias("source"), "target.statement_hash = source.statement_hash")
        .whenMatchedUpdate(set=update_cols)
        .whenNotMatchedInsert(values=insert_cols)
        .execute()
    )

    log_pipeline_stage(spark, "merge", staged_features_df.select(
        F.col("statement_hash"),
        F.lit("SUCCESS").alias("status"),
        F.lit(duration).alias("duration_sec"),
        F.lit(None).cast("string").alias("error"),
    ))
    # Gold is the last stage -- invalidate_downstream("merge", ...) would be
    # a no-op anyway, so it's intentionally omitted here
    print(f"Wrote features for {row_count} new statement(s) -> {TBL_GOLD_ACCOUNT_FEATURES}")

except Exception as e:
    duration = round(time.time() - t0, 3)
    log_pipeline_stage(spark, "merge", new_eligible.select(
        F.col("statement_hash"),
        F.lit("FAILED").alias("status"),
        F.lit(duration).alias("duration_sec"),
        F.lit(str(e)[:500]).alias("error"),
    ))
    raise  # still surface the failure to the Databricks Job UI -- logging supplements, doesn't hide it
