package de.fraunhofer.sit.sse.secqualitycorrelation.database;

import java.io.IOException;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

import com.j256.ormlite.dao.Dao;
import com.j256.ormlite.dao.DaoManager;
import com.j256.ormlite.jdbc.JdbcConnectionSource;
import com.j256.ormlite.support.ConnectionSource;
import com.j256.ormlite.table.TableUtils;

import de.codeinspect.assessment.client.models.Job;

/**
 * Database manager for accessing the computed correlations
 * 
 * @author Steven Arzt
 *
 */
public class DatabaseManager {

	private final String dbUrl;
	private final String userName;
	private final String password;

	public DatabaseManager(String dbUrl, String userName, String password) throws IOException, SQLException {
		this.dbUrl = dbUrl;
		this.userName = userName;
		this.password = password;

		ensureTables();
	}

	/**
	 * Ensures that all required tables exist
	 * 
	 * @throws SQLException
	 * @throws IOException
	 */
	private void ensureTables() throws IOException, SQLException {
		try (ConnectionSource cs = new JdbcConnectionSource(dbUrl, userName, password)) {
			TableUtils.createTableIfNotExists(cs, ProcessedJob.class);
			TableUtils.createTableIfNotExists(cs, CategoryAndCount.class);
			TableUtils.createTableIfNotExists(cs, VulnerabilityAndCount.class);
			TableUtils.createTableIfNotExists(cs, VulnerabilityCorrelation.class);
			TableUtils.createTableIfNotExists(cs, CategoryCorrelation.class);
		}
	}

	/**
	 * Gets which processes have not yet been processed
	 * 
	 * @param jobs The jobs to check
	 * @return The subset of jobs that have not yet been processed
	 * @throws SQLException
	 * @throws IOException
	 */
	public List<Job> getUnprocessedJobs(Collection<Job> jobs) throws IOException, SQLException {
		List<Job> subset = new ArrayList<>(jobs.size());
		try (ConnectionSource cs = new JdbcConnectionSource(dbUrl, userName, password)) {
			Dao<ProcessedJob, String> dao = DaoManager.createDao(cs, ProcessedJob.class);
			for (Job j : jobs) {
				if (!dao.idExists(j.getId().toString()))
					subset.add(j);
			}
		}
		return subset;
	}

	/**
	 * Adds the given job data to the database
	 * 
	 * @param job The job data to add
	 * @throws SQLException
	 * @throws IOException
	 */
	public void addToDatabase(ProcessedJob job) throws SQLException, IOException {
		try (ConnectionSource cs = new JdbcConnectionSource(dbUrl, userName, password)) {
			Dao<ProcessedJob, String> dao = DaoManager.createDao(cs, ProcessedJob.class);
			dao.create(job);
		}
	}

	/**
	 * Adds the given category and count association to the database
	 * 
	 * @param cc The data object to add
	 * @throws SQLException
	 * @throws IOException
	 */
	public void addToDatabase(CategoryAndCount cc) throws SQLException, IOException {
		try (ConnectionSource cs = new JdbcConnectionSource(dbUrl, userName, password)) {
			Dao<CategoryAndCount, String> dao = DaoManager.createDao(cs, CategoryAndCount.class);
			dao.create(cc);
		}
	}

	/**
	 * Adds the given vulnerability and count association to the database
	 * 
	 * @param vc The data object to add
	 * @throws SQLException
	 * @throws IOException
	 */
	public void addToDatabase(VulnerabilityAndCount vc) throws SQLException, IOException {
		try (ConnectionSource cs = new JdbcConnectionSource(dbUrl, userName, password)) {
			Dao<VulnerabilityAndCount, String> dao = DaoManager.createDao(cs, VulnerabilityAndCount.class);
			dao.create(vc);
		}
	}

	/**
	 * Adds the given category correlation to the database
	 * 
	 * @param cc The data object to add
	 * @throws SQLException
	 * @throws IOException
	 */
	public void addToDatabase(CategoryCorrelation cc) throws IOException, SQLException {
		try (ConnectionSource cs = new JdbcConnectionSource(dbUrl, userName, password)) {
			Dao<CategoryCorrelation, String> dao = DaoManager.createDao(cs, CategoryCorrelation.class);
			dao.create(cc);
		}
	}

	/**
	 * Adds the given vulnerability correlation to the database
	 * 
	 * @param vc The data object to add
	 * @throws SQLException
	 * @throws IOException
	 */
	public void addToDatabase(VulnerabilityCorrelation vc) throws IOException, SQLException {
		try (ConnectionSource cs = new JdbcConnectionSource(dbUrl, userName, password)) {
			Dao<VulnerabilityCorrelation, String> dao = DaoManager.createDao(cs, VulnerabilityCorrelation.class);
			dao.create(vc);
		}
	}

	/**
	 * Splits the list of jobs into processed and unprocessed jobs
	 * 
	 * @param jobs            The full list of jobs
	 * @param unprocessedJobs The target list to which to add the jobs that haven't
	 *                        been processed yet
	 * @param processedJobs   The target list to which to add all jobs that have
	 *                        already been processed
	 * @throws SQLException
	 * @throws IOException
	 */
	public void splitJobs(List<Job> jobs, List<Job> unprocessedJobs, List<Job> processedJobs)
			throws IOException, SQLException {
		try (ConnectionSource cs = new JdbcConnectionSource(dbUrl, userName, password)) {
			Dao<ProcessedJob, String> dao = DaoManager.createDao(cs, ProcessedJob.class);
			for (Job j : jobs) {
				if (dao.idExists(j.getId().toString()))
					processedJobs.add(j);
				else
					unprocessedJobs.add(j);
			}
		}
	}

	/**
	 * Gets the job with the given ID
	 * 
	 * @param id The job ID
	 * @return The job with the given ID or <code>null</code> if no such job exists
	 * @throws SQLException
	 * @throws IOException
	 */
	public ProcessedJob getProcessedJob(Long id) throws IOException, SQLException {
		try (ConnectionSource cs = new JdbcConnectionSource(dbUrl, userName, password)) {
			Dao<ProcessedJob, String> dao = DaoManager.createDao(cs, ProcessedJob.class);
			return dao.queryForId(id.toString());
		}
	}

	/**
	 * Gets the list of jobs that correspond to the given list of job IDs
	 * 
	 * @param jobIDs The list of job IDs
	 * @return The list of jobs that correspond to the given list of job IDs
	 * @throws SQLException
	 * @throws IOException
	 */
	public List<ProcessedJob> getProcessedJobs(List<Long> jobIDs) throws SQLException, IOException {
		try (ConnectionSource cs = new JdbcConnectionSource(dbUrl, userName, password)) {
			Dao<ProcessedJob, String> dao = DaoManager.createDao(cs, ProcessedJob.class);
			return jobIDs.stream().map(j -> {
				try {
					return dao.queryForId(j.toString());
				} catch (SQLException e) {
					return null;
				}
			}).collect(Collectors.toList());
		}
	}

	/**
	 * Gets all jobs that have been processed so far
	 * 
	 * @return A list with all jobs that have been processed so far
	 * @throws SQLException
	 * @throws IOException
	 */
	public List<ProcessedJob> getAllProcessedJobs() throws IOException, SQLException {
		try (ConnectionSource cs = new JdbcConnectionSource(dbUrl, userName, password)) {
			Dao<ProcessedJob, String> dao = DaoManager.createDao(cs, ProcessedJob.class);
			return dao.queryForAll();
		}
	}

	/**
	 * Checks whether we have already previous computed a correlation between the
	 * given two types of vulnerabilities
	 * 
	 * @param type1 The first type of vulnerability
	 * @param type2 The second type of vulnerability
	 * @return True if the database already contains a correlation between the two
	 *         types of vulnerabilities, false otherwise
	 * @throws SQLException
	 * @throws IOException
	 */
	public boolean hasVulnerabilityCorrelation(String type1, String type2) throws IOException, SQLException {
		try (ConnectionSource cs = new JdbcConnectionSource(dbUrl, userName, password)) {
			Dao<VulnerabilityCorrelation, String> dao = DaoManager.createDao(cs, VulnerabilityCorrelation.class);
			if (dao.queryBuilder().where().eq("vulnType1", type1).and().eq("vulnType2", type2).countOf() > 0)
				return true;
			if (dao.queryBuilder().where().eq("vulnType2", type1).and().eq("vulnType1", type2).countOf() > 0)
				return true;
		}
		return false;
	}

	/**
	 * Checks whether we have already previous computed a correlation between the
	 * given two types of categories
	 * 
	 * @param type1 The first type of category
	 * @param type2 The second type of category
	 * @return True if the database already contains a correlation between the two
	 *         types of categories, false otherwise
	 * @throws SQLException
	 * @throws IOException
	 */
	public boolean hasCategoryCorrelation(String type1, String type2) throws IOException, SQLException {
		try (ConnectionSource cs = new JdbcConnectionSource(dbUrl, userName, password)) {
			Dao<CategoryCorrelation, String> dao = DaoManager.createDao(cs, CategoryCorrelation.class);
			if (dao.queryBuilder().where().eq("catType1", type1).and().eq("catType2", type2).countOf() > 0)
				return true;
			if (dao.queryBuilder().where().eq("catType2", type1).and().eq("catType1", type2).countOf() > 0)
				return true;
		}
		return false;
	}

}
