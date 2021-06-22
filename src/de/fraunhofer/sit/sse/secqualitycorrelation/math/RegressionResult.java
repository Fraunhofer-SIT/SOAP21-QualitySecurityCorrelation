package de.fraunhofer.sit.sse.secqualitycorrelation.math;

/**
 * Result of a regression on data points
 * 
 * @author Steven Arzt
 *
 * @param <E> The type of resulting function
 */
public class RegressionResult<E extends IMathFunction> {

	protected final E function;
	protected final double quality;

	public RegressionResult(E function, double quality) {
		this.function = function;
		this.quality = quality;
	}

	/**
	 * Gets the function computed by the regression
	 * 
	 * @return The function computed by the regression
	 */
	public E getFunction() {
		return function;
	}

	/**
	 * Gets the quality of the regression. This is usually based on the distance
	 * between the function and the original data points.
	 * 
	 * @return The quality of the function estimated by the regression
	 */
	public double getQuality() {
		return quality;
	}

	@Override
	public String toString() {
		return function.toString();
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((function == null) ? 0 : function.hashCode());
		long temp;
		temp = Double.doubleToLongBits(quality);
		result = prime * result + (int) (temp ^ (temp >>> 32));
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		RegressionResult<?> other = (RegressionResult<?>) obj;
		if (function == null) {
			if (other.function != null)
				return false;
		} else if (!function.equals(other.function))
			return false;
		if (Double.doubleToLongBits(quality) != Double.doubleToLongBits(other.quality))
			return false;
		return true;
	}

}
