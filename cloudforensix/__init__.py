"""CloudForensiX: a forensic-ready monitoring and incident-response framework for
multi-tenant clouds.

The framework operationalises the investigation guidelines of Manral et al.,
"A Systematic Survey on Cloud Forensics Challenges, Solutions, and Future
Directions" (ACM CSUR 52(6), 2019):

* continuous (pre-incident) forensics through centralised, tamper-evident
  logging (Sec. 3.1, 4.1, 8.2.2)          -> :mod:`cloudforensix.seclog`
* heterogeneous log aggregation, time normalisation and correlation for event
  reconstruction (Sec. 4.1, 8.2.2)        -> :mod:`cloudforensix.normalizer`,
                                             :mod:`cloudforensix.correlation`
* live detection with "quick alerts and minimum false positives" (Sec. 7.2)
                                          -> :mod:`cloudforensix.detector`
* privacy-preserving evidence isolation in multi-tenant clouds (Sec. 8.2.4)
                                          -> :mod:`cloudforensix.isolation`
* chain of custody and evidence integrity (Sec. 5, 8.2.5)
                                          -> :mod:`cloudforensix.custody`
* stakeholder artifact map and CSP-dependency analysis (Sec. 8.1, Table 14)
                                          -> :mod:`cloudforensix.artifacts`
* forensic metrics, a gap identified in Sec. 7.2
                                          -> :mod:`cloudforensix.metrics`
"""

__version__ = "1.0.0"
