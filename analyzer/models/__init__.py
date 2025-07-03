import importlib


def create_model(version, segment_size):
    module = importlib.import_module(f'analyzer.models.v{version}')
    return module.create_model(segment_size)
