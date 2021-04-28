# SOAP21-QualitySecurityCorrelation
In this paper, we provide the artifacts for the SOAP'21 paper on the correlation between security and quality issues in Android apps.

## What is the paper about?
In our paper on paper called "Security and Quality: Two Sides of The Same Coin?" that we published on the 10th ACM SIGPLAN International Workshop on the State of the Art in Program Analysis, we investigated whether there is a correlation between the number of security-related findings and the number of code quality-related findings that a static code scanner detects in an Android app. We found the two types of scanner findings to be significantly correlated. We further elaborate on correlations between individual categories of findings in the paper.

## What does the artifact do?
The artifact we publish in this repository connects to a [VUSC](https://secure-software.io/) code scanner and downloads the meta data of all finished Jobs. It writes the data relevant for our statistics (total number of security/quality findings, number of findings per category) into a MySQL database. From this data, it then computes the Spearman correlation coefficients between security findings and quality findings in general, as well as between individual categories of findings. We organize the MySQL database such that incremental updates are possible. If not all analysis jobs in VUSC have completed yet, and the statistics tool is re-run, it adds the missing jobs and re-computes the correlations.

In addition to the correlation computations, the tool also performs computes statistics (how many classes, methods, statements) over apps. Further, it can plot the counts that serve as inputs for the correlation computation using LaTeX / pgfplots. Each plot is a scatter plot, since we don't make any assumptions about the type of correlation (if any). For visualization, the tool nevertheless additionally adds a linear regression.

## How to compile the artifact?
Since the tool downloads data from a VUSC server, it needs to be compiled against the VUSC SDK. We strongly recommend to import the contents of the repository into VDE (VUSC Development Environment). This ensures that you have all the dependencies in place. You can also compile the code using Maven, but you will then need to insert the URL of a Maven repository that provides the VUSC SDK. Once the VUSC team has a public Maven repository, we'll add that to the POM.
