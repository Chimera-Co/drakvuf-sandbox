import logging
import pathlib

from drakrun.lib.config import DrakrunConfig

from ..analysis_metadata import AnalysisMetadata
from .plugins import POSTPROCESS_PLUGINS
from .plugins.plugin_base import PostprocessContext, PostprocessPlugin

logger = logging.getLogger(__name__)

# Postprocess plugins that only understand one guest's logs (options.guest_os)
GUEST_OS_ONLY = {
    "capa_analysis": "windows",
    "process_dumps": "windows",
    "process_linux_dumps": "linux",
    "get_http_info": "windows",
    "get_modified_files_info": "windows",
    "get_socket_info": "windows",
    "generate_wireshark_key_file": "windows",
    "screenshot_metadata": "windows",
    "get_linux_behaviour_info": "linux",
}


def check_plugin_requirements(
    analysis_dir: pathlib.Path, plugin: PostprocessPlugin
) -> bool:
    plugin_name = plugin.function.__name__
    for required_path in plugin.requires:
        if not (analysis_dir / required_path).exists():
            logger.warning(
                f"{plugin_name} won't be run because {required_path} does not exist"
            )
            return False
    for generated_path in plugin.generates:
        if (analysis_dir / generated_path).exists():
            logger.warning(
                f"{plugin_name} won't be run because {generated_path} already exists"
            )
            return False
    return True


def run_postprocessing(context: PostprocessContext):
    # Recorded in metadata so a report can't silently omit a failed step.
    outcomes = {}
    for plugin in POSTPROCESS_PLUGINS:
        plugin_name = plugin.function.__name__
        if plugin_name == "classify_sample" and not context.config.classifier.enabled:
            outcomes[plugin_name] = "skipped"
            continue
        if plugin_name in GUEST_OS_ONLY and context.options.guest_os != GUEST_OS_ONLY[plugin_name]:
            outcomes[plugin_name] = "skipped"
            continue
        if not check_plugin_requirements(context.analysis_dir, plugin):
            outcomes[plugin_name] = "skipped"
            continue
        try:
            plugin.function(context)
            outcomes[plugin_name] = "ok"
        except Exception as e:
            logger.exception(f"{plugin_name} failed with uncaught exception")
            outcomes[plugin_name] = f"failed: {type(e).__name__}"
    context.update_metadata({"postprocess": outcomes})


def postprocess_analysis_dir(
    analysis_dir: pathlib.Path, config: DrakrunConfig, metadata: AnalysisMetadata
):
    context = PostprocessContext(
        analysis_dir=analysis_dir,
        config=config,
        metadata=metadata,
    )
    run_postprocessing(context)
    return context.extra_metadata
