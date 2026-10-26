import os

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "svc.settings")

import django  # noqa: E402

django.setup()
