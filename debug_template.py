import os
import django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'ByteGuard_Project.settings')
django.setup()
for app_config in django.apps.apps.get_app_configs():
    if app_config.name == 'ByteGuard_ai':
        print('FOUND', app_config.name)
        print('path=', app_config.path)
        print('templates exists', os.path.isdir(os.path.join(app_config.path,'templates')))
        print('ByteGuard_ai/templates exists', os.path.isdir(os.path.join(app_config.path,'templates','ByteGuard_ai')))
        print('contents', os.listdir(os.path.join(app_config.path,'templates','ByteGuard_ai')))
