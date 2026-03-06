# Copyright (C) 2026-present MongoDB, Inc.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the Server Side Public License, version 1,
# as published by MongoDB, Inc.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# Server Side Public License for more details.
#
# You should have received a copy of the Server Side Public License
# along with this program. If not, see
# <http://www.mongodb.com/licensing/server-side-public-license>.
#
# As a special exception, the copyright holders give permission to link the
# code of portions of this program with the OpenSSL library under certain
# conditions as described in each individual source file and distribute
# linked combinations including the program with the OpenSSL library. You
# must comply with the Server Side Public License in all respects for
# all of the code used other than as permitted herein. If you modify file(s)
# with this exception, you may extend this exception to your version of the
# file(s), but you are not obligated to do so. If you do not wish to do so,
# delete this exception statement from your version. If you delete this
# exception statement from all source files in the program, then also delete
# it in the license file.
#
"""
Join Cost Model Calibration entry point.

Assumptions:
- The WiredTiger cache is large enough (≥ 100 MB) to contain the join
  calibration collection. If the WT cache were too small, the CPU
  measurements would be invalid.
"""

import asyncio
import os
import random

from data_generator import DataGenerator
from join_calibration_settings import (
    COLLECTION_CARDINALITY,
    join_data_generator,
    join_database,
)
from mongod_manager import MongodManager
from scipy.stats import trim_mean

# Removing 10% on each extreme end of the execution times to remove outliers.
TRIMMED_MEAN_PROPORTION = 0.1


async def calibrate_cpu(manager: MongodManager, num_runs: int = 30):
    """
    Measures the pure CPU cost of processing one tuple (time_tuple).

    After a cold restart, three full collection scans warm the WT cache so all
    data pages are in memory. Subsequent scans incur zero disk I/O, isolating CPU
    overhead.

    The cost model charges a CPU cost for every processed *and* outputted document,
    so time_tuple = (total scan time) / (2*N) where N is the collection cardinality.

    Returns the per-tuple CPU cost in milliseconds.
    """
    print(f"\n=== CPU Calibration ({num_runs} warm scans on join_coll_1) ===")

    manager.restart_cold()
    for _ in range(3):
        await manager.database.explain("join_coll_1", {})
    print("  WT cache warmed (3 full scans)")

    times_ns = []
    for i in range(num_runs):
        explain = await manager.database.explain("join_coll_1", {})
        t = explain["executionStats"]["executionStages"]["executionTimeNanos"]
        times_ns.append(t)
        print(f"  [{i + 1}/{num_runs}] warm scan: {t / 1e6:.3f}ms")

    mean_ns = trim_mean(times_ns, proportiontocut=TRIMMED_MEAN_PROPORTION)
    time_tuple_ns = mean_ns / (2 * COLLECTION_CARDINALITY)
    time_tuple_ms = time_tuple_ns / 1e6

    print("\n--- CPU summary ---")
    print(f"  Mean warm scan: {mean_ns / 1e6:.3f}ms")
    print(f"  time_tuple: {time_tuple_ns:.1f}ns ({time_tuple_ms:.6f}ms)")

    return time_tuple_ms


async def calibrate_sequential_io(
    manager: MongodManager,
    warm_scan_ms: float,
    num_runs: int = 50,
):
    """
    Measures the cost of sequentially reading one WT leaf page from disk.

    We do a "cold restart" (stop mongod, flush OS cache, restart mongod) between every run.
    That empties both the WT cache and the OS page cache, so the subsequent full collection
    scan reads every page from disk.

    Because a cold scan includes CPU work as well as I/O, we subtract the previously
    measured warm-scan time (warm_scan_ms), which should capture the pure CPU component,
    from each cold-scan measurement. This avoids double-counting CPU work.

    Returns the per-leaf-page sequential I/O cost in milliseconds.
    """
    print(f"\n=== Sequential I/O ({num_runs} cold scans on join_coll_1) ===")

    times_ns = []
    for i in range(num_runs):
        manager.restart_cold()
        explain = await manager.database.explain("join_coll_1", {})
        t = explain["executionStats"]["executionStages"]["executionTimeNanos"]
        times_ns.append(t - warm_scan_ms * 1e6)
        print(f"  [{i + 1}/{num_runs}] cold scan: {t / 1e6:.3f}ms")

    mean_ms = trim_mean(times_ns, proportiontocut=TRIMMED_MEAN_PROPORTION) / 1e6
    stats = await manager.database.get_stats("join_coll_1")
    num_leaf_pages = stats["wiredTiger"]["btree"]["row-store leaf pages"]
    mean_per_page_ms = mean_ms / num_leaf_pages

    print("\n--- Sequential I/O summary ---")
    print(f"  Mean cold scan: {mean_ms:.3f}ms")
    print(f"  Leaf pages: {num_leaf_pages}")
    print(f"  Mean per leaf page: {mean_per_page_ms:.5f}ms")

    return mean_per_page_ms


async def calibrate_random_io(manager: MongodManager, num_lookups: int = 100):
    """
    Measures the cost of one random data-page read (the FETCH stage after an index lookup).

    We do a single cold restart followed by one warmup query which loads the index B-tree
    internal structure into the WT cache. Before each subsequent lookup, the OS cache is
    flushed to avoid nearby data pages being cached (e.g., by read-ahead policies).

    We report the FETCH time (total - IXSCAN) because that is the actual random I/O time
    required for retrieving a data page. We don't subtract any double-counted CPU cost
    here, because it's negligible for a single tuple. Note that we're also not taking
    B-tree height into account yet (see SERVER-117523).

    Returns the per-page random I/O cost in milliseconds.
    """
    print(f"\n=== Random I/O ({num_lookups} cold lookups on join_coll_2) ===")

    # Space values evenly across the key range so no two values land on the same WT data page
    step = COLLECTION_CARDINALITY // (num_lookups + 1)
    population = range(1, COLLECTION_CARDINALITY + 1, step)
    msg = f"Not enough evenly-spaced keys: need {num_lookups + 1}, have {len(population)}"
    assert len(population) >= num_lookups + 1, msg
    values = random.sample(population, num_lookups + 1)

    manager.restart_cold()
    await manager.database.explain("join_coll_2", {"filter": {"unique": values[0]}})
    print("  Warmup done (B-tree structure cached in WT)")

    times_ns = []
    for i, val in enumerate(values[1:]):
        manager.flush_os_cache()

        explain = await manager.database.explain("join_coll_2", {"filter": {"unique": val}})
        stages = explain["executionStats"]["executionStages"]
        total_ns = stages["executionTimeNanos"]
        ix_ns = stages["inputStage"]["executionTimeNanos"]
        fetch_ns = total_ns - ix_ns

        times_ns.append(fetch_ns)
        print(
            f"  [{i + 1}/{num_lookups}] unique={val}  "
            f"total={total_ns / 1e6:.3f}ms  ix={ix_ns / 1e6:.3f}ms  fetch={fetch_ns / 1e6:.3f}ms"
        )

    fetch_mean_ms = trim_mean(times_ns, proportiontocut=TRIMMED_MEAN_PROPORTION) / 1e6

    print("\n--- Random I/O summary ---")
    print(f"  FETCH mean: {fetch_mean_ms:.3f}ms")

    return fetch_mean_ms


async def main():
    """Entry point function."""
    script_directory = os.path.abspath(os.path.dirname(__file__))
    os.chdir(script_directory)

    repo_root = os.path.abspath(os.path.join(script_directory, "..", ".."))
    mongod_bin = os.path.join(repo_root, "bazel-bin", "install-mongod", "bin", "mongod")

    with MongodManager(
        mongod_bin,
        db_config=join_database,
        dbpath="~/mongo/join_calibration_db",
        extra_args=[
            # To be able to retrieve the WT "row-store leaf pages" statistic
            "--wiredTigerStatisticsSetting",
            "all",
            "--setParameter",
            "internalMeasureQueryExecutionTimeInNanoseconds=true",
        ],
    ) as manager:
        generator = DataGenerator(manager.database, join_data_generator)
        await generator.populate_collections()

        time_tuple_ms = await calibrate_cpu(manager)
        time_seq_page_ms = await calibrate_sequential_io(
            manager, warm_scan_ms=2 * time_tuple_ms * COLLECTION_CARDINALITY
        )
        time_rand_page_ms = await calibrate_random_io(manager)

        print("\n=== Cost Coefficient Ratios ===")
        print(f"  cpuFactor    = 1.0 ({time_tuple_ms:.6f}ms)")
        print(
            f"  seqIOFactor  = {time_seq_page_ms / time_tuple_ms:.1f}"
            f"  ({time_seq_page_ms:.4f}ms / {time_tuple_ms:.6f}ms)"
        )
        print(
            f"  randIOFactor = {time_rand_page_ms / time_tuple_ms:.1f}"
            f"  ({time_rand_page_ms:.4f}ms / {time_tuple_ms:.6f}ms)"
        )

    print("DONE!")


if __name__ == "__main__":
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
