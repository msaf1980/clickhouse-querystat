package main

import (
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"fmt"
	"io/ioutil"
	stdlog "log"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/araddon/dateparse"
	"github.com/mailru/go-clickhouse"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/rs/zerolog/pkgerrors"
	"github.com/urfave/cli/v2"
)

func main() {
	app := cli.NewApp()
	app.Name = "clickhouse-flamegraph"
	app.Usage = "visualize clickhouse system.trace_log as flamegraph, based on https://gist.github.com/alexey-milovidov/92758583dd41c24c360fdb8d6a4da194"
	app.ArgsUsage = ""
	app.HideHelp = false
	app.Version = "0.0.1"
	app.Flags = []cli.Flag{
		&cli.StringFlag{
			Name:    "date-from",
			Aliases: []string{"from"},
			Usage:   "filter system.trace_log from date in any parsable format, see https://github.com/araddon/dateparse",
			EnvVars: []string{"CH_FLAME_DATE_FROM"},
			Value:   time.Now().Add(time.Duration(-5) * time.Minute).Format("2006-01-02 15:04:05 -0700"),
		},
		&cli.StringFlag{
			Name:    "date-to",
			Aliases: []string{"to"},
			Usage:   "filter system.trace_log to date in any parsable format, see https://github.com/araddon/dateparse",
			EnvVars: []string{"CH_FLAME_DATE_TO"},
			Value:   time.Now().Format("2006-01-02 15:04:05 -0700"),
		},
		&cli.StringFlag{
			Name:    "query-filter",
			Aliases: []string{"query-regexp"},
			Usage:   "filter system.query_log by any regexp, see https://github.com/google/re2/wiki/Syntax",
			EnvVars: []string{"CH_FLAME_QUERY_FILTER"},
			Value:   "",
		},
		&cli.StringSliceFlag{
			Name:    "query-ids",
			Aliases: []string{"query-id"},
			Usage:   "filter system.query_log by query_id field, comma separated list",
			EnvVars: []string{"CH_FLAME_QUERY_IDS"},
			Value:   cli.NewStringSlice(),
		},
		&cli.StringFlag{
			Name:    "clickhouse-dsn",
			Aliases: []string{"dsn"},
			Usage:   "clickhouse connection string, see https://github.com/mailru/go-clickhouse#dsn",
			EnvVars: []string{"CH_FLAME_CLICKHOUSE_DSN"},
			Value:   "http://localhost:8123/default",
		},
		&cli.StringFlag{
			Name:    "clickhouse-cluster",
			Aliases: []string{"cluster"},
			Usage:   "clickhouse cluster name from system.clusters, all flame graphs will get from cluster() function, see https://clickhouse.tech/docs/en/sql-reference/table-functions/cluster",
			EnvVars: []string{"CH_FLAME_CLICKHOUSE_CLUSTER"},
			Value:   "",
		},
		&cli.StringFlag{
			Name:    "tls-certificate",
			Usage:   "X509 *.cer, *.crt or *.pem file for https connection, use only if tls_config exists in --dsn, see https://clickhouse.tech/docs/en/operations/server-configuration-parameters/settings/#server_configuration_parameters-openssl for details",
			EnvVars: []string{"CH_FLAME_TLS_CERT"},
			Value:   "",
		},
		&cli.StringFlag{
			Name:    "tls-key",
			Usage:   "X509 *.key file for https connection, use only if tls_config exists in --dsn",
			EnvVars: []string{"CH_FLAME_TLS_KEY"},
			Value:   "",
		},
		&cli.StringFlag{
			Name:    "tls-ca",
			Usage:   "X509 *.cer, *.crt or *.pem file used with https connection for self-signed certificate, use only if tls_config exists in --dsn, see https://clickhouse.tech/docs/en/operations/server-configuration-parameters/settings/#server_configuration_parameters-openssl for details",
			EnvVars: []string{"CH_FLAME_TLS_CA"},
			Value:   "",
		},
		&cli.BoolFlag{
			Name:    "normalize-query",
			Aliases: []string{"normalize"},
			Usage:   "group stack by normalized queries, instead of query_id, see https://clickhouse.tech/docs/en/sql-reference/functions/string-functions/#normalized-query",
			EnvVars: []string{"CH_FLAME_NORMALIZE_QUERY"},
		},
		&cli.BoolFlag{
			Name:    "debug",
			Aliases: []string{"verbose"},
			Usage:   "show debug log",
			EnvVars: []string{"CH_FLAME_DEBUG"},
		},
		&cli.BoolFlag{
			Name:    "console",
			Usage:   "output logs to console format instead of json",
			EnvVars: []string{"CH_FLAME_LOG_TO_CONSOLE"},
		},
	}

	app.Action = run
	if err := app.Run(os.Args); err != nil {
		log.Fatal().Err(err).Msg("generation failed")
	}
}

var (
	querySQLTemplate = `
SELECT hostName() AS host_name, {queryField}, {queryIdField},
       user, client_hostname, client_name, http_user_agent,
	   event_time, query_duration_ms,
	   read_rows, read_bytes,
	   written_rows, written_bytes,
	   result_rows, result_bytes,
	   memory_usage, current_database,
	   thread_ids,
	   ProfileEvents.Names as profile_names,
       ProfileEvents.Values as profile_values
FROM {from}
WHERE {where}
`
)

func run(c *cli.Context) error {
	stdlog.SetOutput(log.Logger)
	zerolog.ErrorStackMarshaler = pkgerrors.MarshalStack
	if c.Bool("verbose") {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	} else {
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	}

	if c.Bool("console") {
		log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stdout})
	}

	return generate(c)
}

func parseDate(c *cli.Context, paramName string) time.Time {
	var parsedDate time.Time
	var err error
	if parsedDate, err = dateparse.ParseAny(c.String(paramName)); err != nil {
		if duration, err := time.ParseDuration(c.String(paramName)); err != nil {
			log.Fatal().Err(err).Msgf("invalid %s parameter = %s", paramName, c.String(paramName))
		} else {
			parsedDate = time.Now().Add(-duration)
		}
	}
	return parsedDate
}

func prepareTLSConfig(dsn string, c *cli.Context) {
	if strings.Contains(dsn, "tls_config") {
		cfg, err := clickhouse.ParseDSN(dsn)
		if err != nil {
			log.Fatal().Stack().Err(errors.Wrap(err, "")).Send()
		}
		tlsConfig := &tls.Config{}
		if c.String("tls-ca") != "" {
			CA := x509.NewCertPool()
			severCert, err := ioutil.ReadFile(c.String("tls-ca"))
			if err != nil {
				log.Fatal().Stack().Err(errors.Wrap(err, "")).
					Str("tls-ca", c.String("tls-ca")).
					Str("tls-certificate", c.String("tls-certificate")).
					Str("tls-key", c.String("tls-key")).
					Send()
			}
			CA.AppendCertsFromPEM(severCert)
			tlsConfig.RootCAs = CA
		}
		if c.String("tls-certificate") != "" {
			cert, err := tls.LoadX509KeyPair(c.String("tls-certificate"), c.String("tls-key"))
			if err != nil {
				log.Fatal().Stack().Err(errors.Wrap(err, "")).
					Str("tls-ca", c.String("tls-ca")).
					Str("tls-certificate", c.String("tls-certificate")).
					Str("tls-key", c.String("tls-key")).
					Send()
			}
			tlsConfig.Certificates = []tls.Certificate{cert}
		}
		if err := clickhouse.RegisterTLSConfig(cfg.TLSConfig, tlsConfig); err != nil {
			log.Fatal().Stack().Err(errors.Wrap(err, "")).Send()
		}
	}
}

func generate(c *cli.Context) error {
	cluster := c.String("clickhouse-cluster")
	queryFilter := c.String("query-filter")
	queryIds := c.StringSlice("query-ids")
	dsn := c.String("dsn")
	dateFrom := parseDate(c, "date-from")
	dateTo := parseDate(c, "date-to")

	prepareTLSConfig(dsn, c)

	db := openDbConnection(dsn)
	checkClickHouseVersion(c, db)
	flushSystemLog(db)

	querySQL, queryArgs := buildQuery(db, cluster, querySQLTemplate, c.Bool("normalize-query"), queryFilter, queryIds, dateFrom, dateTo)
	fetchQuery(db, querySQL, queryArgs, func(r map[string]interface{}) error {
		hostName := r["host_name"].(string)
		queryId := r["query_id"].(string)
		query := r["query"].(string)

		username := r["user"].(string)
		clientHostname := r["client_hostname"].(string)
		clientName := r["client_name"].(string)
		httpUserAgent := r["http_user_agent"].(string)

		eventTime := r["event_time"].(time.Time)
		queryDurationMs := r["query_duration_ms"].(uint64)
		readRows := r["read_rows"].(uint64)
		readBytes := r["read_bytes"].(uint64)
		writtenRows := r["written_rows"].(uint64)
		writtenBytes := r["written_bytes"].(uint64)
		resultRows := r["result_rows"].(uint64)
		resultBytes := r["result_bytes"].(uint64)
		memoryUsage := r["memory_usage"].(uint64)
		currentDatabase := r["current_database"].(string)

		//threadIds := r["thread_ids"].([]uint64)
		profileNames := r["profile_names"].([]string)
		profileValues := r["profile_values"].([]uint64)

		fmt.Printf("\n\n%s\n", query)
		fmt.Printf("\tQuery ID %s at %v", queryId, eventTime)
		if len(cluster) > 0 {
			fmt.Printf(" (cluster %s)\n", cluster)
		} else {
			fmt.Printf(" (hostname %s)\n", hostName)
		}
		fmt.Printf("\tUser %s from %s", username, clientHostname)
		if len(clientName) > 0 {
			fmt.Printf(", client %s", clientName)
		}
		if len(httpUserAgent) > 0 {
			fmt.Printf(", http user agent %s", httpUserAgent)
		}

		fmt.Printf("\n\n%20s %11s %10s %10s %10s %10s %10s %10s %10s\n",
			"current_database", "duration_ms",
			"read_rows", "read_byte",
			"write_rows", "write_byte",
			"res_rows", "res_byte",
			"memory_use",
		)
		fmt.Printf("%20s %11d %10d %10d %10d %10d %10d %10d %10d\n",
			currentDatabase, queryDurationMs,
			readRows, readBytes,
			writtenRows, writtenBytes,
			resultRows, resultBytes,
			memoryUsage,
		)
		if len(profileNames) > 0 {
			fmt.Printf("\tProfile stat\n")
			for i := 0; i < len(profileNames) && i < len(profileValues); i++ {
				fmt.Printf("%50s %10d\n", profileNames[i], profileValues[i])
			}
		}

		fmt.Printf("\n")

		return nil
	})

	return nil
}

func flushSystemLog(db *sql.DB) {
	if _, err := db.Exec("SYSTEM FLUSH LOGS"); err != nil {
		log.Fatal().Stack().Err(errors.Wrap(err, "")).Msg("SYSTEM FLUSH LOGS failed")
	}
}

func parseClickhouseVersion(versionStr string) ([]int, error) {
	split := strings.Split(versionStr, ".")
	if len(split) < 2 {
		return nil, fmt.Errorf("can't parse clickhouse version: '%s'", versionStr)
	}
	version := make([]int, len(split))
	var err error
	for i := range split {
		if version[i], err = strconv.Atoi(split[i]); err != nil {
			break
		}
	}
	return version, err
}

func checkClickHouseVersion(c *cli.Context, db *sql.DB) {
	fetchQuery(db, "SELECT version() AS version", nil, func(r map[string]interface{}) error {
		version, err := parseClickhouseVersion(r["version"].(string))
		if err != nil {
			log.Fatal().Str("version", r["version"].(string)).Err(err)
		}
		if (version[0] == 20 && version[1] < 6) && c.Bool("normalize-query") {
			log.Fatal().Str("version", r["version"].(string)).Msg("normalize-query require ClickHouse server version 20.6+")
		}
		if version[0] < 20 || (version[0] == 20 && version[1] < 5) {
			log.Fatal().Str("version", r["version"].(string)).Msg("system.trace_log with trace_type require ClickHouse server version 20.5+")
		}
		return nil
	})
}

func openDbConnection(dsn string) *sql.DB {
	db, err := sql.Open("clickhouse", dsn)
	if err != nil {
		log.Fatal().Str("dsn", dsn).Err(err).Msg("Can't establishment ClickHouse connection")
	} else {
		log.Info().Str("dsn", dsn).Msg("connected to ClickHouse")
	}
	return db
}

func addWhereArgs(where, addWhere string, args []interface{}, addArg interface{}) (string, []interface{}) {
	where += addWhere
	if addArg != nil {
		args = append(args, addArg)
	}
	return where, args
}

func buildQuery(db *sql.DB, cluster, querySQLTemplate string, normalize bool, queryFilter string, queryIds []string, dateFrom time.Time, dateTo time.Time) (string, []interface{}) {
	var queryField, queryIdField, queryLogTable string

	queryArgs := []interface{}{dateFrom, dateTo}
	queryWhere := "event_time >= ? AND event_time <= ?"

	if cluster != "" {
		queryLogTable = "clusterAllReplicas('" + cluster + "', system.query_log) AS q"
	} else {
		queryLogTable = "system.query_log AS q"
	}

	if normalize {
		queryField = "normalizeQuery(q.query) AS query"
		queryIdField = "toString(normalizedQueryHash(q.query)) AS query_id"
	} else {
		queryField = "q.query"
		queryIdField = "q.query_id"
	}

	if queryFilter != "" {
		if _, err := regexp.Compile(queryFilter); err != nil {
			log.Fatal().Err(err).Str("queryFilter", queryFilter).Msg("Invalid regexp")
		}
		queryWhere, queryArgs = addWhereArgs(queryWhere, " AND match(query, ?) ", queryArgs, queryFilter)
	}
	if len(queryIds) != 0 {
		queryWhere, queryArgs = addWhereArgs(queryWhere, " AND query_id IN ('"+strings.Join(queryIds, "','")+"') ", queryArgs, nil)
	}

	querySQL := formatSQLTemplate(
		querySQLTemplate,
		map[string]interface{}{
			"where":        queryWhere,
			"from":         queryLogTable,
			"queryField":   queryField,
			"queryIdField": queryIdField,
		},
	)

	return querySQL, queryArgs
}

// formatSQLTemplate use simple {key_from_context} template syntax
func formatSQLTemplate(sqlTemplate string, context map[string]interface{}) string {
	args, i := make([]string, len(context)*2), 0
	for k, v := range context {
		args[i] = "{" + k + "}"
		args[i+1] = fmt.Sprint(v)
		i += 2
	}
	return strings.NewReplacer(args...).Replace(sqlTemplate)
}

//fetchRowAsMap see https://kylewbanks.com/blog/query-result-to-map-in-golang
func fetchRowAsMap(rows *sql.Rows, cols []string) (m map[string]interface{}, err error) {
	// Create a slice of interface{}'s to represent each column,
	// and a second slice to contain pointers to each item in the columns slice.
	columns := make([]interface{}, len(cols))
	columnPointers := make([]interface{}, len(cols))
	for i := range columns {
		columnPointers[i] = &columns[i]
	}

	// Scan the result into the column pointers...
	if err := rows.Scan(columnPointers...); err != nil {
		return nil, err
	}

	// Create our map, and retrieve the value for each column from the pointers slice,
	// storing it in the map with the name of the column as the key.
	m = make(map[string]interface{}, len(cols))
	for i, colName := range cols {
		val := columnPointers[i].(*interface{})
		m[colName] = *val
	}
	return m, nil
}

func fetchQuery(db *sql.DB, sql string, sqlArgs []interface{}, fetchCallback func(r map[string]interface{}) error) {
	rows, err := db.Query(sql, sqlArgs...)
	if err != nil {
		log.Fatal().Stack().Err(errors.Wrap(err, "")).Str("sql", sql).Str("sqlArgs", fmt.Sprintf("%v", sqlArgs)).Send()
	} else {
		log.Debug().Str("sql", sql).Str("sqlArgs", fmt.Sprintf("%v", sqlArgs)).Msg("query OK")
	}
	cols, _ := rows.Columns()
	for rows.Next() {
		r, err := fetchRowAsMap(rows, cols)
		if err != nil {
			log.Fatal().Stack().Err(errors.Wrap(err, "")).Msg("fetch error")
		}
		if err := fetchCallback(r); err != nil {
			log.Fatal().Stack().Err(errors.Wrap(err, "")).Msg("fetch error")
		}
	}
	if err := rows.Close(); err != nil {
		log.Fatal().Stack().Err(errors.Wrap(err, "")).Interface("rows", rows).Send()
	}
}
