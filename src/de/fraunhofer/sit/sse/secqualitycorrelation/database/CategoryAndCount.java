package de.fraunhofer.sit.sse.secqualitycorrelation.database;

import com.j256.ormlite.field.DatabaseField;
import com.j256.ormlite.table.DatabaseTable;

/**
 * The association with the category name and the respective counts
 * 
 * @author Steven Arzt
 *
 */
@DatabaseTable(tableName = "CategoriesAndCounts")
public class CategoryAndCount {

	@DatabaseField(generatedId = true)
	public long id;

	@DatabaseField(foreign = true)
	public ProcessedJob job;

	@DatabaseField
	public String category;

	@DatabaseField
	public int count;

	public CategoryAndCount() {
	}

	public CategoryAndCount(ProcessedJob job, String cat, Integer count) {
		this.job = job;
		this.category = cat;
		this.count = count;
	}

}
