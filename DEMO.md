# Demonstration workflow

From the project directory:

```text
python vapt_mvp.py
python -m unittest discover -s tests -v
```

The first command checks the authorized Juice Shop lab and creates paired reports in `reports/`. The second command verifies the project without contacting the target.

For the restricted tool adapter:

```text
echo {"name":"vapt_scope"} | python mcp_tools.py
```

Review the target and obtain approval before running an assessment through an agent workflow.
