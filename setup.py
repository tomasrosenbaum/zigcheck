from setuptools import setup, find_namespace_packages

setup(
      include_package_data=True,
      name='zigcheck',
      version='0.1',
      packages=find_namespace_packages(),
      install_requires=['Click'],
      entry_points={
            'console_scripts': [
                  'zigcheck = zigcheck.main:scan'
            ],
      },
)