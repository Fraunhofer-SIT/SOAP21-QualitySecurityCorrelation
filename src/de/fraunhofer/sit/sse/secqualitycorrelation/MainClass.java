package de.fraunhofer.sit.sse.secqualitycorrelation;

import java.io.File;
import java.io.IOException;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Random;
import java.util.Set;
import java.util.stream.Collectors;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.apache.commons.lang3.tuple.ImmutablePair;
import org.apache.commons.lang3.tuple.Pair;
import org.apache.commons.math3.linear.OpenMapRealMatrix;
import org.apache.commons.math3.stat.correlation.SpearmansCorrelation;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.core.LoggerContext;
import org.apache.logging.log4j.core.config.Configurator;

import de.codeinspect.assessment.client.api.JobsApi;
import de.codeinspect.assessment.client.invoker.ApiClient;
import de.codeinspect.assessment.client.invoker.ApiException;
import de.codeinspect.assessment.client.models.DetailedJobStatus;
import de.codeinspect.assessment.client.models.Job;
import de.codeinspect.assessment.client.models.JobResults;
import de.codeinspect.assessment.client.models.VulnerabilityFinding;
import de.codeinspect.collections.CountingMap;
import de.codeinspect.tables.CountingTable;
import de.fraunhofer.sit.sse.secqualitycorrelation.database.CategoryAndCount;
import de.fraunhofer.sit.sse.secqualitycorrelation.database.CategoryCorrelation;
import de.fraunhofer.sit.sse.secqualitycorrelation.database.DatabaseManager;
import de.fraunhofer.sit.sse.secqualitycorrelation.database.ProcessedJob;
import de.fraunhofer.sit.sse.secqualitycorrelation.database.VulnerabilityAndCount;
import de.fraunhofer.sit.sse.secqualitycorrelation.database.VulnerabilityCorrelation;

/**
 * Main class for security and quality correlation analysis
 * 
 * @author Steven Arzt
 *
 */
public class MainClass {

	private static final int NUM_PERMUTATIONS = 100;
	private static final float SIGNIFICANCE_ERROR_PROBABILITY = 0.05f;
	private static final int DEFAULT_CUTOFF = 30000;

	private static Logger logger;

	private static final String OPTION_DB_URL = "d";
	private static final String OPTION_DB_USER = "u";
	private static final String OPTION_DB_PWD = "w";

	private static final String OPTION_VUSC_URL = "v";
	private static final String OPTION_CUTOFF = "c";

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

		options.addOption(OPTION_VUSC_URL, "vuscurl", true, "The URL for accessing the VUSC scanner");
		options.addOption(OPTION_CUTOFF, "cutoff", true, "The cutoff (max. number of issues) when to discard apps");
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
				logger = context.getLogger(MainClass.class);
		}
		if (logger == null)
			logger = LogManager.getLogger(MainClass.class);

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

			int cutoff = DEFAULT_CUTOFF;
			String s = cmd.getOptionValue(OPTION_CUTOFF);
			if (s != null && !s.isEmpty())
				cutoff = Integer.valueOf(s);

			// Connect to the VUSC server
			String vuscURL = cmd.getOptionValue(OPTION_VUSC_URL);
			ApiClient apiClient = new ApiClient();
			apiClient.setBasePath(vuscURL);
			apiClient.setReadTimeout(0);

			// Get all jobs from the VUSC server
			logger.info("Retrieving jobs from VUSC server...");
			JobsApi jobsApi = new JobsApi(apiClient);
			List<Job> jobs = jobsApi.getJobs(false, null, null, null, null);
			logger.info(String.format("Retrieved %d jobs from VUSC server", jobs.size()));

			// If we analyzed the same app multiple times, we only use the copy with the
			// fewest errors
			outer: for (Iterator<Job> it = jobs.iterator(); it.hasNext();) {
				Job j = it.next();
				for (Job j2 : jobs) {
					if (j != j2 && j.getMetadata().getSha256Hash().equals(j2.getMetadata().getSha256Hash())) {
						if (getFailureCount(j) > getFailureCount(j2)) {
							it.remove();
							continue outer;
						}
					}
				}

				// Remove jobs for which we have no data
				if (j.getStatus().getFinishedAnalyses() == 0) {
					it.remove();
				}
			}
			logger.info(String.format("After cleanup, we have %d jobs left", jobs.size()));

			// Get the jobs that still need to be analyzed
			List<Job> unprocessedJobs = new ArrayList<>();
			List<Job> processedJobs = new ArrayList<>();
			dbManager.splitJobs(jobs, unprocessedJobs, processedJobs);
			logger.info(String.format("We have %d jobs that we haven't processed yet", unprocessedJobs.size()));

			// Analyze the new jobs
			CountingTable<Job, String> catMap = new CountingTable<>();
			CountingTable<Job, String> vulnMap = new CountingTable<>();
			CountingTable<Job, CategoryType> typeMap = new CountingTable<>();
			for (Job j : unprocessedJobs) {
				// We need to explicitly load each job to get the job results
				logger.info(String.format("Analyzing job %d...", j.getId()));
				j = jobsApi.getJob(j.getId());
				JobResults results = j.getJobResults();

				if (results != null) {
					// Create the metadata record
					ProcessedJob pj = new ProcessedJob();
					pj.jobId = j.getId();
					List<VulnerabilityFinding> findings = results.getVulnerabilityFindings();
					if (findings != null) {
						pj.numQualFindings = (int) findings.stream().filter(f -> isCodeQualityCategory(f)).count();
						pj.numSecFindings = (int) findings.stream().filter(f -> !isCodeQualityCategory(f)).count();

						if (pj.numQualFindings > cutoff || pj.numSecFindings > cutoff)
							continue;

						// Map categories to finding counts
						CountingMap<String> projectVulnMap = new CountingMap<>();
						CountingMap<String> projectCatMap = new CountingMap<>();
						CountingMap<CategoryType> projectTypeMap = new CountingMap<>();
						for (VulnerabilityFinding f : findings) {
							projectVulnMap.increment(f.getType());
							projectCatMap.increment(f.getCategory());
							projectTypeMap.increment(isCodeQualityCategory(f) ? CategoryType.QualityCategory
									: CategoryType.SecurityCategory);
						}

						vulnMap.addAll(j, projectVulnMap);
						catMap.addAll(j, projectCatMap);
						typeMap.addAll(j, projectTypeMap);

						pj.categoriesToCounts = new HashSet<>();
						for (String cat : projectCatMap.keySet()) {
							CategoryAndCount cc = new CategoryAndCount(pj, cat, projectCatMap.get(cat));
							pj.categoriesToCounts.add(cc);
							dbManager.addToDatabase(cc);
						}
						pj.vulnerabilitiesToCounts = new HashSet<>();
						for (String vuln : projectVulnMap.keySet()) {
							VulnerabilityAndCount vc = new VulnerabilityAndCount(pj, vuln, projectVulnMap.get(vuln));
							pj.vulnerabilitiesToCounts.add(vc);
							dbManager.addToDatabase(vc);
						}
					}
					dbManager.addToDatabase(pj);
				}
			}

			// Load the counts for the existing jobs from the database
			List<ProcessedJob> resolvedProcessedJobs = dbManager
					.getProcessedJobs(processedJobs.stream().map(j -> j.getId()).collect(Collectors.toList()));
			for (int i = 0; i < resolvedProcessedJobs.size(); i++) {
				ProcessedJob pj = resolvedProcessedJobs.get(i);
				Job j = processedJobs.get(i);
				if (pj.categoriesToCounts != null) {
					for (CategoryAndCount cc : pj.categoriesToCounts) {
						catMap.add(j, cc.category, cc.count);
						typeMap.add(j, cc.category.equals("Code Quality") ? CategoryType.QualityCategory
								: CategoryType.SecurityCategory, cc.count);
					}
				}
				if (pj.vulnerabilitiesToCounts != null) {
					for (VulnerabilityAndCount vc : pj.vulnerabilitiesToCounts) {
						vulnMap.add(j, vc.vulnType, vc.count);
					}
				}
			}

			// Compute the overall correlation between security and quality
			int[] qualityVals = typeMap.columnValues(CategoryType.QualityCategory,
					(a, b) -> a.getId().compareTo(b.getId()));
			int[] securityVals = typeMap.columnValues(CategoryType.SecurityCategory,
					(a, b) -> a.getId().compareTo(b.getId()));
			double correlation = correlate(qualityVals, securityVals);
			double significance = computeSignificance(qualityVals, securityVals);
			logger.info(String.format(
					"Overall correlation between security and quality issues is %.2f (significance is %.2f)",
					correlation, significance));

			// Compute pairwise correlations between categories
			{
				Set<Pair<String, String>> computedPairs = new HashSet<>();
				for (String cat1 : catMap.getColumns()) {
					for (String cat2 : catMap.getColumns()) {
						if (computedPairs.add(new ImmutablePair<>(cat1, cat2))) {
							if (!cat1.equals(cat2)) {
								correlateCategories(catMap, cat1, cat2, dbManager);
							}
						}
					}
				}
			}

			// Compute pairwise correlations between issue types
			{
				Set<Pair<String, String>> computedPairs = new HashSet<>();
				for (String type1 : vulnMap.getColumns()) {
					for (String type2 : vulnMap.getColumns()) {
						if (computedPairs.add(new ImmutablePair<>(type1, type2))) {
							if (!type1.equals(type2)) {
								correlateIssueTypes(vulnMap, type1, type2, dbManager);
							}
						}
					}
				}
			}
		} catch (ParseException e) {
			formatter.printHelp("java -jar CorrelationAnalysis.jar [OPTIONS]", options);
			return;
		} catch (ApiException e) {
			logger.error("Error during communication with VUSC", e);
		} catch (IOException e) {
			logger.error("IO error during correlation analysis", e);
		} catch (SQLException e) {
			logger.error("SQL error on backend database for correlations", e);
		}
	}

	/**
	 * Computes the correlation between the two vectors
	 * 
	 * @param vals1 The first vector
	 * @param vals2 The second vector
	 * @return The correlation between the two vectors
	 */
	protected static double correlate(int[] vals1, int[] vals2) {
		OpenMapRealMatrix dataMatrix = new OpenMapRealMatrix(vals1.length, 2);
		SpearmansCorrelation sc = new SpearmansCorrelation(dataMatrix);
		double correlation = sc.correlation(Arrays.stream(vals1).asDoubleStream().toArray(),
				Arrays.stream(vals2).asDoubleStream().toArray());
		return correlation;
	}

	/**
	 * Correlates the given categories
	 * 
	 * @param vulnMap   The counting map that contains the number of findings per
	 *                  category
	 * @param cat1      The first category
	 * @param cat2      The second category
	 * @param dbManager The database manager
	 * @throws SQLException
	 * @throws IOException
	 */
	private static void correlateCategories(CountingTable<Job, String> vulnMap, String cat1, String cat2,
			DatabaseManager dbManager) throws IOException, SQLException {
		// Do we already know this correlation?
		if (!dbManager.hasCategoryCorrelation(cat1, cat2)) {
			double correlation = correlate(vulnMap, cat1, cat2);
			double significance = computeSignificance(vulnMap, cat1, cat2);
			if (Math.abs(correlation) > Math.abs(significance))
				logger.info(String.format(
						"HIGH Overall correlation between categories %s and %s is %.2f (significance is %.2f)", cat1,
						cat2, correlation, significance));
			else
				logger.info(
						String.format("Overall correlation between categories %s and %s is %.2f (significance is %.2f)",
								cat1, cat2, correlation, significance));

			CategoryCorrelation cc = new CategoryCorrelation(cat1, cat2, correlation);
			cc.significance = significance;
			dbManager.addToDatabase(cc);
		}
	}

	/**
	 * Correlates the given issue types
	 * 
	 * @param vulnMap   The counting map that contains the number of findings per
	 *                  issue type
	 * @param type1     The first issue type
	 * @param type2     The second issue type
	 * @param dbManager The database manager
	 * @throws SQLException
	 * @throws IOException
	 */
	private static void correlateIssueTypes(CountingTable<Job, String> typeMap, String type1, String type2,
			DatabaseManager dbManager) throws IOException, SQLException {
		// Do we already know this correlation?
		if (!dbManager.hasVulnerabilityCorrelation(type1, type2)) {
			double correlation = correlate(typeMap, type1, type2);
			double significance = computeSignificance(typeMap, type1, type2);
			if (Math.abs(correlation) > Math.abs(significance))
				logger.info(String.format(
						"HIGH Overall correlation between issue types %s and %s is %.2f (significance is %.2f)", type1,
						type2, correlation, significance));
			else
				logger.info(String.format(
						"Overall correlation between issue types %s and %s is %.2f (significance is %.2f)", type1,
						type2, correlation, significance));

			VulnerabilityCorrelation vc = new VulnerabilityCorrelation(type1, type2, correlation);
			vc.significance = significance;
			dbManager.addToDatabase(vc);
		}
	}

	/**
	 * Gets the value above which correlation coefficients are assumed to be
	 * non-random
	 * 
	 * @param vals1 The first vector of counts
	 * @param vals2 The second vector of counts
	 * @return The value above which correlation coefficients are assumed to be
	 *         non-random
	 */
	private static double computeSignificance(int[] vals1, int[] vals2) {
		List<Double> randomCorrelations = new ArrayList<>();
		Random rnd = new Random();
		for (int i = 0; i < NUM_PERMUTATIONS; i++) {
			int[] newVals1 = new int[vals1.length];
			int[] newVals2 = new int[vals2.length];
			System.arraycopy(vals1, 0, newVals1, 0, vals1.length);
			System.arraycopy(vals2, 0, newVals1, 0, vals2.length);

			for (int j = 0; j < vals1.length; j++) {
				if (rnd.nextBoolean()) {
					newVals1[j] = vals2[j];
					newVals2[j] = vals1[j];
				}
			}
			double correlation = correlate(newVals1, newVals2);
			if (!Double.isNaN(correlation))
				randomCorrelations.add(correlation);
		}
		randomCorrelations.sort(Double::compare);

		// We assume that the top and bottom x% of the random distribution can be
		// considered random with an x% error probability
		int baseIdx = (int) Math.floor(((float) randomCorrelations.size()) * (1f - SIGNIFICANCE_ERROR_PROBABILITY));
		return randomCorrelations.get(baseIdx);
	}

	/**
	 * Gets the value above which correlation coefficients are assumed to be
	 * non-random
	 * 
	 * @param map  The counting map that contains the number of findings per
	 *             category or vulnerability type
	 * @param cat1 The first category
	 * @param cat2 The second category
	 * @return The value above which correlation coefficients are assumed to be
	 *         non-random
	 */
	private static double computeSignificance(CountingTable<Job, String> map, String cat1, String cat2) {
		List<Double> randomCorrelations = new ArrayList<>();
		Random rnd = new Random();
		for (int i = 0; i < NUM_PERMUTATIONS; i++) {
			CountingTable<Job, String> newTbl = new CountingTable<>(map);
			for (Job j : map.rowKeySet()) {
				if (rnd.nextBoolean()) {
					newTbl.remove(j, cat1);
					newTbl.remove(j, cat2);
					newTbl.put(j, cat1, map.get(j, cat2));
					newTbl.put(j, cat2, map.get(j, cat1));
				}
			}
			double correlation = correlate(newTbl, cat1, cat2);
			if (!Double.isNaN(correlation))
				randomCorrelations.add(correlation);
		}
		if (randomCorrelations.isEmpty())
			return 0;

		randomCorrelations.sort(Double::compare);

		// We assume that the top and bottom x% of the random distribution can be
		// considered random with an x% error probability
		int baseIdx = (int) Math.floor(((float) randomCorrelations.size()) * (1f - SIGNIFICANCE_ERROR_PROBABILITY));
		return randomCorrelations.get(baseIdx);
	}

	/**
	 * Correlates the given categories
	 * 
	 * @param map  The counting map that contains the number of findings per
	 *             category or vulnerability type
	 * @param cat1 The first category
	 * @param cat2 The second category
	 * @return The correlation
	 * @throws SQLException
	 * @throws IOException
	 */
	private static double correlate(CountingTable<Job, String> map, String cat1, String cat2) {
		OpenMapRealMatrix dataMatrix = new OpenMapRealMatrix(map.rowCount(), 2);
		SpearmansCorrelation sc = new SpearmansCorrelation(dataMatrix);
		int[] qualityVals = map.columnValues(cat1, (a, b) -> a.getId().compareTo(b.getId()));
		int[] securityVals = map.columnValues(cat2, (a, b) -> a.getId().compareTo(b.getId()));
		return sc.correlation(Arrays.stream(qualityVals).asDoubleStream().toArray(),
				Arrays.stream(securityVals).asDoubleStream().toArray());
	}

	/**
	 * Checks whether the given finding belongs to a code quality category
	 * 
	 * @param f The finding to check
	 * @return True if the given finding belongs to a code quality category, false
	 *         otherwise
	 */
	protected static boolean isCodeQualityCategory(VulnerabilityFinding f) {
		return f.getCategory().equals("Code Quality");
	}

	/**
	 * Gets the number of failures in the given job
	 * 
	 * @param j The job to check
	 * @return The number of failures in the given job
	 */
	private static int getFailureCount(Job j) {
		DetailedJobStatus status = j.getStatus();
		if (status != null) {
			if (status.getFinishDate() > 0)
				return status.getFailedAnalyses();
		}
		return Integer.MAX_VALUE;
	}

}
