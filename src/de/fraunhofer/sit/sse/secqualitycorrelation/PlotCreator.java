package de.fraunhofer.sit.sse.secqualitycorrelation;

import java.io.File;
import java.io.IOException;
import java.nio.charset.Charset;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.apache.commons.io.FilenameUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.core.LoggerContext;
import org.apache.logging.log4j.core.config.Configurator;

import com.google.common.io.FileWriteMode;
import com.google.common.io.Files;

import de.codeinspect.collections.CountingMap;
import de.codeinspect.tables.CountingTable;
import de.fraunhofer.sit.sse.secqualitycorrelation.database.CategoryAndCount;
import de.fraunhofer.sit.sse.secqualitycorrelation.database.DatabaseManager;
import de.fraunhofer.sit.sse.secqualitycorrelation.database.ProcessedJob;
import de.fraunhofer.sit.sse.secqualitycorrelation.database.VulnerabilityAndCount;
import de.fraunhofer.sit.sse.secqualitycorrelation.math.CorrelationAnalysis;
import de.fraunhofer.sit.sse.secqualitycorrelation.math.LinearFunction;
import de.fraunhofer.sit.sse.secqualitycorrelation.math.RegressionResult;
import soot.util.HashMultiMap;
import soot.util.MultiMap;

/**
 * Class for creating the plots
 * 
 * @author Steven Arzt
 *
 */
public class PlotCreator {

	private static Logger logger;

	private static final String OPTION_DB_URL = "d";
	private static final String OPTION_DB_USER = "u";
	private static final String OPTION_DB_PWD = "w";

	private static final String OPTION_OUTPUT_DIR = "p";

	protected static final Options options = new Options();

	static {
		initializeCommandLineOptions();
	}

	/**
	 * Initializes the set of available command-line options
	 */
	private static void initializeCommandLineOptions() {
		options.addOption(OPTION_DB_URL, "dburl", true, "The JDBC url for connecting to the database");
		options.addOption(OPTION_DB_USER, "dbuser", true, "The user for accessing the database");
		options.addOption(OPTION_DB_PWD, "dbpwd", true, "The password for accessing the database");

		options.addOption(OPTION_OUTPUT_DIR, "vuscurl", true, "The output directory for the plots");
	}

	public static void main(String[] args) {
		// Explicitly load log configuration
		File logConfigFile = new File("log4j2.properties");
		if (logConfigFile.exists()) {
			System.out.println(String.format("Loading log configuration from %s", logConfigFile.getAbsolutePath()));
			LoggerContext context = Configurator.initialize(null, logConfigFile.toURI().toString());
			if (context == null)
				System.err.println("Could not load log configuration file");
			else
				logger = context.getLogger(PlotCreator.class);
		}
		if (logger == null)
			logger = LogManager.getLogger(PlotCreator.class);

		// We need proper parameters
		final HelpFormatter formatter = new HelpFormatter();
		if (args.length == 0) {
			formatter.printHelp("java -jar CorrelationAnalysis.jar [OPTIONS]", options);
			return;
		}
		CommandLineParser parser = new DefaultParser();
		try {
			CommandLine cmd = parser.parse(options, args);

			// Get the database details
			String dbUrl = cmd.getOptionValue(OPTION_DB_URL);
			String dbUser = cmd.getOptionValue(OPTION_DB_USER);
			String dbPwd = cmd.getOptionValue(OPTION_DB_PWD);
			if (dbUrl == null || dbUrl.isEmpty() || dbUser == null || dbUser.isEmpty() || dbPwd == null
					|| dbPwd.isEmpty()) {
				logger.error("Database url, user, or password not specified");
				return;
			}
			DatabaseManager dbManager = new DatabaseManager(dbUrl, dbUser, dbPwd);

			// Load the counts for the existing jobs from the database
			CountingTable<ProcessedJob, String> catMap = new CountingTable<>();
			CountingTable<ProcessedJob, String> vulnMap = new CountingTable<>();
			CountingTable<ProcessedJob, String> typeMap = new CountingTable<>();
			List<ProcessedJob> resolvedProcessedJobs = dbManager.getAllProcessedJobs();
			for (int i = 0; i < resolvedProcessedJobs.size(); i++) {
				ProcessedJob pj = resolvedProcessedJobs.get(i);
				if (pj.categoriesToCounts != null) {
					for (CategoryAndCount cc : pj.categoriesToCounts) {
						catMap.add(pj, cc.category, cc.count);
						typeMap.add(pj, cc.category.equals("Code Quality") ? cc.category : "Security", cc.count);
					}
				}
				if (pj.vulnerabilitiesToCounts != null) {
					for (VulnerabilityAndCount vc : pj.vulnerabilitiesToCounts) {
						vulnMap.add(pj, vc.vulnType, vc.count);
					}
				}
			}

			// Load the template file
			final String template = Files.asCharSource(new File("correlation.tex"), Charset.defaultCharset()).read();

			// Create the category-to-category plots
			File outputDir = new File(cmd.getOptionValue(OPTION_OUTPUT_DIR));
			generateTexFiles(typeMap, template, outputDir, "Total_");
			generateTexFiles(catMap, template, outputDir, "Cat_");
			System.out.println(String.format("Writing out %d vulnerability mappings...", vulnMap.size()));
			generateTexFiles(vulnMap, template, outputDir, "Vuln_");
		} catch (ParseException e) {
			formatter.printHelp("java -jar CorrelationAnalysis.jar [OPTIONS]", options);
			return;
		} catch (SQLException e) {
			logger.error("SQL error on backend database for correlations", e);
		} catch (IOException e) {
			logger.error("IO error during correlation analysis", e);
		}
	}

	protected static void generateTexFiles(CountingTable<ProcessedJob, String> issueMap, final String template,
			File outputDir, String filePrefix) throws IOException {
		ExecutorService executor = new ThreadPoolExecutor(25, 25, 60L, TimeUnit.SECONDS, new LinkedBlockingQueue<>());
		Set<String> doneSet = new HashSet<>();
		Set<String> categories = issueMap.columnKeySet();
		for (String cat1 : categories) {
			for (String cat2 : categories) {
				if (!cat1.equals(cat2) && !doneSet.contains(cat2)) {
					executor.execute(new Runnable() {

						@Override
						public void run() {
							CountingMap<ProcessedJob> cat1Counts = (CountingMap<ProcessedJob>) issueMap.column(cat1);
							CountingMap<ProcessedJob> cat2Counts = (CountingMap<ProcessedJob>) issueMap.column(cat2);

							StringBuilder catValues = getCountsFromMap(cat1Counts, cat2Counts);

							String texCode = template;
							texCode = texCode.replace("CATNAME1", cat1.replaceAll("\\_", "\\\\_"));
							texCode = texCode.replace("CATNAME2", cat2.replaceAll("\\_", "\\\\_"));
							texCode = texCode.replace("%CAT1", catValues);

							String texCode2 = template;
							texCode2 = texCode2.replace("CATNAME1", cat1.replaceAll("\\_", "\\\\_"));
							texCode2 = texCode2.replace("CATNAME2", cat2.replaceAll("\\_", "\\\\_"));

							// Compute linear interpolation
							CountingTable<ProcessedJob, String> monotonousTbl = new CountingTable<>(issueMap);
							resolveColDuplicates(monotonousTbl, cat1);

							int[] v1 = monotonousTbl.columnValues(cat1,
									(a, b) -> monotonousTbl.get(a, cat1) - monotonousTbl.get(b, cat1));
							int[] v2 = monotonousTbl.columnValues(cat2,
									(a, b) -> monotonousTbl.get(a, cat1) - monotonousTbl.get(b, cat1));

							StringBuilder catValues2 = getCountsFromMap(v1, v2);
							texCode2 = texCode2.replace("%CAT1", catValues2);

							double[] d1 = Arrays.stream(v1).asDoubleStream().toArray();
							double[] d2 = Arrays.stream(v2).asDoubleStream().toArray();

							RegressionResult<LinearFunction> res = CorrelationAnalysis.calculateLinearRegression(d1,
									d2);
							LinearFunction func = res.getFunction();
							if (!func.isValid())
								return;

							texCode = texCode.replace("$a$", String.format("%.2f", func.getA()).replace(",", "."));
							texCode = texCode.replace("$b$", String.format("%.2f", func.getB()).replace(",", "."));
							texCode = texCode.replace("$QUALITY$",
									String.format("%.2f", res.getQuality()).replace(",", "."));

							texCode2 = texCode2.replace("$a$", String.format("%.2f", func.getA()).replace(",", "."));
							texCode2 = texCode2.replace("$b$", String.format("%.2f", func.getB()).replace(",", "."));
							texCode2 = texCode2.replace("$QUALITY$",
									String.format("%.2f", res.getQuality()).replace(",", "."));

							double xmin = Double.MAX_VALUE;
							double xmax = Double.MIN_VALUE;
							for (ProcessedJob pj : cat1Counts.keySet()) {
								xmin = Math.min(xmin, cat1Counts.get(pj));
								xmax = Math.max(xmax, cat1Counts.get(pj));
							}
							if (Math.round(xmin * 100) == Math.round(xmax * 100))
								return;

							texCode = texCode.replace("$xmin", String.format("%.2f", xmin).replace(",", "."));
							texCode = texCode.replace("$xmax", String.format("%.2f", xmax).replace(",", "."));

							texCode2 = texCode2.replace("$xmin", String.format("%.2f", xmin).replace(",", "."));
							texCode2 = texCode2.replace("$xmax", String.format("%.2f", xmax).replace(",", "."));

							// Compile the TEX source
							File outputFile = new File(outputDir, filePrefix + cat1 + "-" + cat2 + ".tex");
							try {
								writeTexFile(outputFile, texCode);
							} catch (IOException e) {
								logger.error(
										String.format("Could not write PDF file for categories %s and %s", cat1, cat2),
										e);
							}
//							File outputFile2 = new File(outputDir, filePrefix + cat1 + "-" + cat2 + "_2.tex");
//							writeTexFile(outputFile2, texCode2);
						}

					});
				}
			}
//			doneSet.add(cat1);
		}
		executor.shutdown();
		try {
			executor.awaitTermination(Integer.MAX_VALUE, TimeUnit.DAYS);
		} catch (InterruptedException e) {
			logger.error("Could not wait for PDF generator tasks to terminate properly", e);
		}
	}

	private static void writeTexFile(File outputFile, String texCode) throws IOException {
		if (outputFile.exists())
			outputFile.delete();
		Files.asCharSink(outputFile, Charset.defaultCharset(), FileWriteMode.APPEND).write(texCode);
		ProcessBuilder pb = new ProcessBuilder("pdflatex", outputFile.getAbsolutePath());
		pb.inheritIO();
		pb.directory(outputFile.getParentFile());
		Process p = pb.start();
		try {
			p.waitFor();
		} catch (InterruptedException e) {
			logger.error("Could not compile plot as TEX file", e);
		}

		// Clean up after ourselves
		String baseName = FilenameUtils.removeExtension(outputFile.getAbsolutePath());
		File auxFile = new File(baseName + ".aux");
		if (auxFile.exists())
			auxFile.delete();
		File logFile = new File(baseName + ".log");
		if (logFile.exists())
			logFile.delete();
	}

	public static <R, C> void resolveColDuplicates(CountingTable<R, C> tbl, C referenceCol) {
		Set<R> rows = tbl.rowKeySet();
		MultiMap<Integer, R> valsToRows = new HashMultiMap<>();
		for (R r : rows) {
			valsToRows.put(tbl.get(r, referenceCol), r);
		}
		for (Integer i : valsToRows.keySet()) {
			Set<R> valRows = valsToRows.get(i);
			if (valRows.size() > 1) {
				// We have the same value in multiple rows, so we need to merge the respective
				// rows
				for (C c2 : tbl.columnKeySet()) {
					List<Integer> duplicateVals = new ArrayList<>();
					for (R r2 : valRows) {
						duplicateVals.add(tbl.get(r2, c2));
					}
					int res = duplicateVals.stream().reduce(0, (a, b) -> a + b) / duplicateVals.size();

					R refRow = valRows.iterator().next();
					tbl.put(refRow, c2, res);
					for (R r2 : valRows) {
						if (r2 != refRow)
							tbl.remove(r2, c2);
					}
				}
			}
		}
	}

	/**
	 * Gets the values in this map as an ordered array
	 * 
	 * @param comparator The comparator that defines the ordering on the values
	 * @return The ordered array of values in this map
	 */
	public <E> int[] values(CountingMap<E> map, Comparator<E> comparator) {
		List<E> ordered = new ArrayList<>(map.keySet());
		ordered.sort(comparator);
		int[] values = new int[ordered.size()];
		for (int i = 0; i < values.length; i++)
			values[i] = map.get(ordered.get(i));
		return values;
	}

	/**
	 * Gets the data points to write into the TEX file
	 * 
	 * @param map1 The map with jobs and counts for category A
	 * @param map2 The map with jobs and counts for category B
	 * @return The data point list to write into the TEX file
	 */
	protected static StringBuilder getCountsFromMap(Map<ProcessedJob, Integer> map1, Map<ProcessedJob, Integer> map2) {
		Set<ProcessedJob> allJobs = new HashSet<>(map1.size() + map2.size());
		allJobs.addAll(map1.keySet());
		allJobs.addAll(map2.keySet());

		StringBuilder cat1Values = new StringBuilder(allJobs.size() * 25);
		for (ProcessedJob pj : allJobs) {
			cat1Values.append(map1.get(pj));
			cat1Values.append('\t');
			cat1Values.append(map2.get(pj));
			cat1Values.append('\n');
		}
		return cat1Values;
	}

	/**
	 * Gets the data points to write into the TEX file
	 * 
	 * @param x The x coordinates
	 * @param y The y coordinates
	 * @return The data point list to write into the TEX file
	 */
	protected static StringBuilder getCountsFromMap(int[] x, int[] y) {
		StringBuilder cat1Values = new StringBuilder(x.length * 25);
		for (int i = 0; i < x.length; i++) {
			cat1Values.append(x[i]);
			cat1Values.append('\t');
			cat1Values.append(y[i]);
			cat1Values.append('\n');
		}
		return cat1Values;
	}

}
