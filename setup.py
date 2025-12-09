    from setuptools import setup, find_packages

    setup(
        name='cybersecuritynchs',
        version='0.2.0',
        description='An MkDocs website for the Cybersecurity Club at NCHS.',
        long_desscription=open('README.md').read(),
        long_description_content_type='text/markdown',
        author='Mohamed Morsy',
        
        packages=find_packages(),
        install_requires=[
            'mkdocs>=1.0.0',
        ],

      # This entry point is crucial for MkDocs to discover the plugin
      # entry_points={
      #     'mkdocs.plugins': [
      #         'xtermjs = mkdocs_xtermjs_plugin.plugin:XtermPlugin',
      #     ]
      # },
        include_package_data=True,
    )
