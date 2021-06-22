package de.fraunhofer.sit.sse.secqualitycorrelation.database;

import java.util.Collection;

import com.j256.ormlite.field.DatabaseField;
import com.j256.ormlite.field.ForeignCollectionField;
import com.j256.ormlite.table.DatabaseTable;

/**
 * A job on which the correlations have been computed
 * 
 * @author Steven Arzt
 *
 */
@DatabaseTable(tableName = "ProcessedJobs")
public class ProcessedJob {

	@DatabaseField(id = true)
	public long jobId;

	@DatabaseField
	public int numSecFindings;
	@DatabaseField
	public int numQualFindings;

	@ForeignCollectionField
	public Collection<CategoryAndCount> categoriesToCounts;

	@ForeignCollectionField
	public Collection<VulnerabilityAndCount> vulnerabilitiesToCounts;

}
