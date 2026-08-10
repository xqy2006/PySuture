from __future__ import annotations

import importlib
import os
import sys

import fltk
import wx


# wxPython intentionally deletes ``core`` from the package namespace after
# re-exporting its public symbols.  Keep the imported module object explicitly
# instead of relying on a non-public ``wx.core`` attribute.
wx_core = importlib.import_module("wx.core")


def main() -> int:
    if not hasattr(wx, "App") or not hasattr(wx, "Frame"):
        return 10
    if not hasattr(fltk, "Fl") or not hasattr(fltk, "Fl_Window"):
        return 11
    if sys.argv[1:] != ["参数 空格", "路径-中文"]:
        return 12
    if wx_core.__file__ != "staticpython-resource:///Lib/wx/core.py":
        return 13
    locale_dir = os.path.join(os.path.dirname(wx_core.__file__), "locale")
    if not os.path.isdir(locale_dir):
        return 14
    if not os.listdir(locale_dir):
        return 15
    print(f"wx={wx.VERSION_STRING}; fltk={fltk.__name__}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
