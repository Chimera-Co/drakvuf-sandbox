from drakrun.lib.log_stats import precompute

from .plugin_base import PostprocessContext


def build_log_stats(context: PostprocessContext) -> None:
    """Summaries for the analysis page, cached next to the logs (log_stats/<log>.json)."""
    precompute(context.analysis_dir)
