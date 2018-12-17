from setuptools import find_packages, setup

setup(
    name='flask_blog',
    version='1.0.0',
    packages=find_packages(),
    include_package_data=True,
    url="https://github.com/jayesh-patil-2/flask-blog/",
    zip_safe=False,
    install_requires=[
        'flask',
    ],
)