from typing import Mapping, Any, Hashable, Dict


def rget(obj: Mapping, *args, default: Any = None):
    if not len(args):
        raise ValueError('argument count cannot be zero')

    end_key = args[-1]
    for key in args[:-1]:
        obj = obj.get(key, {})

    return obj.get(end_key, default)


def recursive_dict_update(source_dict: Dict[Hashable, Any], merge_map: Mapping[Hashable, Any]) -> Dict[Hashable, Any]:
    for key, value in merge_map.items():
        if key in source_dict and isinstance(merge_map[key], Mapping) and isinstance(source_dict[key], Mapping):
            if not isinstance(source_dict[key], dict):
                source_dict[key] = dict(source_dict[key])
            recursive_dict_update(source_dict[key], merge_map[key])
        else:
            source_dict[key] = merge_map[key]

    return source_dict
