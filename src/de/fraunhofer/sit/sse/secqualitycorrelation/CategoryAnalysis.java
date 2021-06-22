package de.fraunhofer.sit.sse.secqualitycorrelation;

import java.io.File;
import java.util.Map;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.core.LoggerContext;
import org.apache.logging.log4j.core.config.Configurator;

import de.codeinspect.assessment.client.api.VulnerabilitiesApi;
import de.codeinspect.assessment.client.invoker.ApiClient;
import de.codeinspect.assessment.client.invoker.ApiException;
import de.codeinspect.assessment.client.models.Platform;
import de.codeinspect.assessment.client.models.VulnerabilityInformation;
import de.codeinspect.collections.CountingMap;

/**
 * Main class for security and quality correlation analysis
 * 
 * @author Steven Arzt
 *
 */
public class CategoryAnalysis {

	private static Logger logger;

	private static final String OPTION_DB_URL = "d";
	private static final String OPTION_DB_USER = "u";
	private static final String OPTION_DB_PWD = "w";

	private static final String OPTION_VUSC_URL = "v";

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
				logger = context.getLogger(CategoryAnalysis.class);
		}
		if (logger == null)
			logger = LogManager.getLogger(CategoryAnalysis.class);

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

			// Connect to the VUSC server
			String vuscURL = cmd.getOptionValue(OPTION_VUSC_URL);
			ApiClient apiClient = new ApiClient();
			apiClient.setBasePath(vuscURL);
			apiClient.setReadTimeout(0);

			VulnerabilitiesApi vulnAPI = new VulnerabilitiesApi(apiClient);
			CountingMap<String> categorySizes = new CountingMap<>();
			int total = 0;
			for (VulnerabilityInformation vuln : vulnAPI.getVulnerabilities()) {
				boolean hasAndroid = false;
				for (Platform p : vuln.getPlatforms()) {
					if (p.getId().equals("ANDROID_APP_APK")) {
						hasAndroid = true;
						break;
					}
				}
				if (hasAndroid) {
					Object cat = vuln.getCategory();
					if (cat instanceof Map) {
						@SuppressWarnings("unchecked")
						Map<String, String> catMap = (Map<String, String>) cat;
						String catName = catMap.get("humanReadableName");
						if (catName != null)
							categorySizes.increment(catName);
					}
					total++;
				}
			}
			System.out.println(categorySizes.toString());
			System.out.println("Total: " + total);
		} catch (ParseException e) {
			formatter.printHelp("java -jar CorrelationAnalysis.jar [OPTIONS]", options);
			return;
		} catch (ApiException e) {
			logger.error("Error during communication with VUSC", e);
		}
	}

}
