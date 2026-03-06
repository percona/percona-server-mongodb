/**
 * Finds metrics files in the given directory.
 * @param {string} directory - The directory path to search in.
 * @returns {Array<Object>} An array of file objects (from listFiles()) whose names end with "-metrics.jsonl". Each file
 *     object has a 'name' property containing the full file path.
 */
function findMetricsFiles(directory) {
    const files = listFiles(directory);
    return files.filter(function (file) {
        if (!file.name.endsWith("-metrics.jsonl")) {
            return false;
        }
        return true;
    });
}

/**
 * Reads and parses a JSONL (JSON Lines) file.
 * @param {string} filePath - The path to the JSONL file.
 * @returns {Array<Object>} An array of parsed JSON objects, one per line in the file.
 *     Returns an empty array if the file is empty, doesn't exist, or if parsing fails
 *     (which can happen if the file is read mid-write).
 */
function readJsonlFile(filePath) {
    const content = cat(filePath);
    if (!content || content.trim() === "") {
        return [];
    }
    const lines = content.trim().split("\n");
    const records = [];
    for (const line of lines) {
        if (!line.trim()) {
            continue;
        }
        let parsedLine;
        try {
            parsedLine = JSON.parse(line);
        } catch (e) {
            // The last record is often cut off due to being read mid-write, but previous records may be valid.
            return records;
        }
        records.push(parsedLine);
    }
    return records;
}

function safeConvertToNumber(value) {
    // Comparing to the MIN and MAX safe integers guarantees that the resulting value is precise, i.e., for numbers
    // outside this range, the result could be rounded to a slightly higher or lower value.
    assert(value >= Number.MIN_SAFE_INTEGER);
    assert(value <= Number.MAX_SAFE_INTEGER);
    return Number(value);
}

/**
 * Finds the latest time from all points in the given record.
 * @param {Object} record - The record to search in.
 * @returns {number} The latest time from all points in the record in milliseconds. Returns 0 if no points are found.
 */
function latestTime(record) {
    let allPoints = [];
    for (const resourceMetric of record?.resourceMetrics ?? []) {
        for (const scopeMetric of resourceMetric.scopeMetrics ?? []) {
            for (const metric of scopeMetric.metrics ?? []) {
                allPoints.push(...(metric.sum?.dataPoints ?? []));
                allPoints.push(...(metric.gauge?.dataPoints ?? []));
                allPoints.push(...(metric.histogram?.dataPoints ?? []));
            }
        }
    }
    return allPoints.length > 0
        ? Math.max(...allPoints.map((point) => safeConvertToNumber(BigInt(point.timeUnixNano) / 1_000_000n)))
        : 0;
}

/**
 * Gets the most recent metrics from the given directory.
 * @param {string} directory - The directory path to search in.
 * @returns {Object} An object with the metric name as the key and the metric value as the value, or null if no metrics
 *  are found. The value is an object with the "value" property containing the metric value for counters and gauges.
 *  Also contains a special "time" property containing the latest time from all points in the record in milliseconds.
 *  Example:
 *  {
 *     "time": 1771619346,
 *     // A counter or gauge metric.
 *     "network.connections_processed": {
 *          "value": 100
 *      },
 *      // A histogram metric.
 *      "network.tls_handshake_latency": {
 *          "count": 100,
 *          "sum": 10000,
 *          "min": 100,
 *          "max": 10000,
 *          "bucketCounts":   [800, 900, 800, 400, 300, 200, 150, 125, 110, 101],
 *          "explicitBounds": [100, 200, 300, 400, 500, 600, 700, 800, 900, 1000]
 *      }
 *      ...
 *  }
 */
export function getLatestMetrics(directory) {
    let record = undefined;
    const files = findMetricsFiles(directory);
    const records = files
        .map((file) => {
            const record = readJsonlFile(file.name);
            if (record.length === 0) {
                jsTest.log.info(`No records found in file ${file.name}`);
            }
            return record;
        })
        .filter((record) => record.length > 0)
        // Each record contains all the metrics, so just return the last, i.e. most recent, one.
        .map((records) => records.at(-1));
    if (records.length === 0) {
        return null;
    }
    // Of all the records from multiple files, take the most recent one.
    record = records.reduce((latest, curRecord) => {
        return latestTime(latest) > latestTime(curRecord) ? latest : curRecord;
    }, records.at(0));

    let metrics = [];
    for (const resourceMetric of record?.resourceMetrics ?? []) {
        for (const scopeMetric of resourceMetric.scopeMetrics ?? []) {
            for (const metric of scopeMetric.metrics ?? []) {
                metrics.push(metric);
            }
        }
    }
    let result = Object.fromEntries(
        metrics.map((metric) => {
            let result = {};
            for (const dataPoint of (metric.sum?.dataPoints ?? []).concat(metric.gauge?.dataPoints ?? [])) {
                if (dataPoint.asInt) {
                    result["value"] ??= 0;
                    result["value"] += Number(dataPoint.asInt);
                } else {
                    result["value"] ??= 0;
                    result["value"] += Number(dataPoint.asDouble);
                }
            }
            for (const dataPoint of metric.histogram?.dataPoints ?? []) {
                // There should only be one data point for the histogram.
                result = dataPoint;
            }
            return [metric.name, result];
        }),
    );
    result.time = latestTime(record);
    return result;
}

/**
 * Generates the name for a metrics directory for the given test name and ensures the directory exists. The name is
 * randomized so the same testName will provide different results on different calls.
 * @param {string} testName - The name of the test.
 * @returns {string} The path to the metrics directory.
 */
export function createMetricsDirectory(testName) {
    if (!Random.isInitialized()) {
        Random.setRandomSeed();
    }
    const metricsDir = MongoRunner.toRealPath(`${testName}_otel_metrics_${Random.randInt(1000000)}`);
    assert(mkdir(metricsDir), `Failed to create metrics directory: ${metricsDir}`);
    return metricsDir;
}
