# """
# Enforcer class that inherits from current enforcer and sets our defaults
# And uses our adapter by default
# """

# from dauthz.core import enforcer

# from .adapter import ExtendedAdapter


# class ExtendedEnforcer(enforcer):
#     """
#     Enforcer class that inherits from current enforcer and sets our defaults
#     And uses our adapter by default
#     """

#     def __init__(self):
#         super().__init__()
#         self.adapter = ExtendedAdapter()

"""
Enforcer instance for openedx_authz.
"""

from dauthz.core import enforcer
from redis_watcher import WatcherOptions, new_watcher


# Define raw ID → type mapper
def classify(obj: str) -> str | None:
    """
    Map raw ID to type.
    """
    if obj.startswith("course-") or obj.startswith("course:"):
        return "course"
    if obj.startswith("lib-") or obj.startswith("lib:"):
        return "lib"
    if obj.startswith("report-") or obj.startswith("report:"):
        return "report"
    if obj.startswith("asset-") or obj.startswith("asset:"):
        return "asset"
    return None


# Custom function type_match
def type_match(obj: str, policy_obj: str) -> bool:
    """
    - If policy_obj == "<type>:*": true if classify(obj) == <type>.
    - In any other case: false.
    """
    if policy_obj.endswith(":*"):
        policy_type = policy_obj.split(":")[0]
        return classify(obj) == policy_type
    return False


def callback_function(event):
    """
    Callback function for the enforcer.
    """
    print("\n\nUpdate for remove filtered policy callback, event: {}".format(event))


def get_enforcer():
    """
    Get the enforcer instance.
    """
    enforcer.enable_auto_save(True)
    watcher_options = WatcherOptions()
    watcher_options.host = "redis"
    watcher_options.port = 6379
    watcher_options.optional_update_callback = callback_function
    watcher = new_watcher(watcher_options)
    enforcer.set_watcher(watcher)
    enforcer.add_function("type_match", type_match)
    return enforcer
