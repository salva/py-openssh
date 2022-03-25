
import logging
import sys
import re

def _compile_matchers(include, exclude):
    assert len(include) > 0
    include = [re.compile(m) for m in include]
    exclude = [re.compile(m) for m in exclude]

    r = "(?!(?:" + ")|(?:".join([m.pattern for m in exclude]) + "))" if exclude else ''
    r += "(?:(?:" + ")|(?:".join([m.pattern for m in include]) + "))"
    logging.debug("regular expression: %s", r)
    return re.compile(r)

def def_revconstant(module_name, *include, exclude=[], prefix='', unknown='unknown-'):
    module = sys.modules[module_name]
    rev = {}

    matcher = _compile_matchers(include, exclude)

    for name in dir(module):
        if matcher.match(name):
            v = str(getattr(module, name))
            if v in rev:
                logging.warn("duplicated constant value %s for %s and %s", v, rev[v], name)
            else:
                rev[v] = name

    def revconstant(constant_value):
        v = str(constant_value)
        if v in rev:
            return prefix + rev[v]
        else:
            return prefix + unknown + v

    return revconstant

