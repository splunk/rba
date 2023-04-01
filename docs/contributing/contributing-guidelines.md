# Contributing Guidelines

!!! tip "All are welcome to contribute!"

A GitHub account is required to create a pull request to submit new content. If you do not want to submit changes, you may also consider the following:

- Submit a **feature request** (issue) at [https://github.com/splunk/rba/issues](https://github.com/splunk/rba/issues){ target=_blank }.
- Create a new discussion at [https://github.com/splunk/rba/discussions](https://github.com/splunk/rba/discussions){ target=_blank }.
- Don't have a GitHub account? Reach out to us on [Slack](https://outpost-security.com/slack){ target=_blank }!

## How to Contribute

This repository uses [MkDocs](https://www.mkdocs.org/){ target=_blank } with the [Material for MkDocs](https://squidfunk.github.io/mkdocs-material/){ target=_blank } theme.

If you know the markdown language then using this style of documentation will be a breeze. For a full list of capabilities see [MkDocs's website](https://squidfunk.github.io/mkdocs-material/reference/).

### Fork the RBA GitHub

- Fork the RBA GitHub page and be sure to submit pull requests to the **development branch only**.
- Before submitting your pull request, merge `development` with your new branch and fix any conflicts.
- Try to match the format of the existing documentation. 

### Create a local environment for testing

Testing locally will be a great way to ensure your changes will work with what currently exists. 

The easiest way to get started is by using a python virtual environment. For simplicity, `pipenv` will be used for the following.

1. Install python and pipenv on your local workstation -> [Pipenv docs](https://pypi.org/project/pipenv/#installation){ target=_blank }.
1. Once installed, navigate to your forked repository and run the following to install the latest requirements.

    ```shell
    # your forked rba directory
    # ./rba
    pipenv install -r docs/requirements.txt
    ```

1. Now you can enter `pipenv run mkdocs serve` which will create a webserver that can be reached by opening your browser and navigating to [http://localhost:8000](http://localhost:8000){ target=_blank }.