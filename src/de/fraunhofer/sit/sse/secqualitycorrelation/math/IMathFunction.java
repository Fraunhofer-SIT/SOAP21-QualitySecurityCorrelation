package de.fraunhofer.sit.sse.secqualitycorrelation.math;

/**
 * Common interface for all mathematical functions
 * 
 * @author Steven Arzt
 *
 */
public interface IMathFunction {

	/**
	 * Computes the linear function at the given point
	 * 
	 * @param x The x value
	 * @return The value f(x)
	 */
	public double compute(double x);

	/**
	 * Checks whether this function is valid. Functions that have NaN coefficients
	 * are never valid.
	 * 
	 * @return True if this function is valid, false otherwise
	 */
	public boolean isValid();

}
