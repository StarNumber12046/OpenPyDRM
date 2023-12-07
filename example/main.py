import OpenPyDrm

drm = OpenPyDrm.PyDrm("1234", "http://localhost:8080")

drm.login()
hello:callable = drm.get_asset("hello")
hello("StarNumber")