package de.fraunhofer.sit.sse.secqualitycorrelation.math;

/**
 * A linear function y=a*x +b
 * 
 * @author Steven Arzt
 *
 */
public class LinearFunction implements IMathFunction {

	protected final double a;
	protected final double b;

	public LinearFunction(double a, double b) {
		this.a = a;
		this.b = b;
	}

	/**
	 * Gets the parameter a of y=a*x +b
	 * 
	 * @return The parameter a
	 */
	public double getA() {
		return a;
	}

	/**
	 * Gets the parameter b of y=a*x +b
	 * 
	 * @return The parameter b
	 */
	public double getB() {
		return b;
	}

	@Override
	public double compute(double x) {
		return a * x + b;
	}

	@Override
	public boolean isValid() {
		return Double.isFinite(a) && Double.isFinite(b);
	}

	@Override
	public String toString() {
		return String.format("y =%.2f*x + %.2f", a, b);
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		long temp;
		temp = Double.doubleToLongBits(a);
		result = prime * result + (int) (temp ^ (temp >>> 32));
		temp = Double.doubleToLongBits(b);
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
		LinearFunction other = (LinearFunction) obj;
		if (Double.doubleToLongBits(a) != Double.doubleToLongBits(other.a))
			return false;
		if (Double.doubleToLongBits(b) != Double.doubleToLongBits(other.b))
			return false;
		return true;
	}

}
