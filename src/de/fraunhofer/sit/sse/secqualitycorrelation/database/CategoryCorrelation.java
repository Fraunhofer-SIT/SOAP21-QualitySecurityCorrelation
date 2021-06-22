package de.fraunhofer.sit.sse.secqualitycorrelation.database;

import com.j256.ormlite.field.DatabaseField;
import com.j256.ormlite.table.DatabaseTable;

/**
 * The association between the category and the respective counts
 * 
 * @author Steven Arzt
 *
 */
@DatabaseTable(tableName = "CategoryCorrelations")
public class CategoryCorrelation {

	@DatabaseField(generatedId = true)
	public long id;

	@DatabaseField
	public String catType1;

	@DatabaseField
	public String catType2;

	@DatabaseField
	public double correlation;

	@DatabaseField
	public double significance;

	public CategoryCorrelation() {
	}

	public CategoryCorrelation(String catType1, String catType2, double correlation) {
		this.catType1 = catType1;
		this.catType2 = catType2;
		this.correlation = correlation;
	}

}
