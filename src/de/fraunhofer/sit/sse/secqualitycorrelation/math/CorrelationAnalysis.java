package de.fraunhofer.sit.sse.secqualitycorrelation.math;

/**
 * Class for function interpolation
 * 
 * @author Steven Arzt
 *
 */
public class CorrelationAnalysis {

	/**
	 * Computes a linear function from the given data points with minimal Gaussian
	 * error
	 * 
	 * @param x The x values. These values must be monotonously increasing.
	 * @param y The y values
	 * @return The estimated linear function
	 */
	public static RegressionResult<LinearFunction> calculateLinearRegression(double[] x, double[] y) {
		if (x.length != y.length)
			throw new IllegalArgumentException("Array must have equal length");

		final int n = x.length;

		// Calculate averages
		double xs = 0;
		double ys = 0;
		for (int i = 0; i < x.length; i++) {
			xs += x[i];
			ys += y[i];
		}
		double xm = xs / n;
		double ym = ys / n;

		// Calculate slope
		double k = 0;
		double l = 0;
		for (int i = 0; i < x.length; i++) {
			k += (x[i] - xm) * (y[i] - ym);
			double temp = (x[i] - xm);
			l += temp * temp;
		}
		double a = k / l;
		double b = ym - a * xm;

		// Calculate error
		double sxy = k / n;
		double sx = xs / n;
		double sy = ys / n;
		double r = sxy / (sx * sy);

		return new RegressionResult<>(new LinearFunction(a, b), r);
	}

}
