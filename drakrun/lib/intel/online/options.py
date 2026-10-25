"""Upload options preserved in queue metadata and the online options artifact."""

from drakrun.analyzer.analysis_options import AnalysisOptions


class OnlineAnalysisOptions(AnalysisOptions):
    intel_online: bool = True
