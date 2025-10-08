Contributing to 'humble' Open Source Project
============================================

<i>humble</i> welcomes contributions. When contributing please follow the [Code of Conduct](https://github.com/rfc-st/humble/blob/master/CODE_OF_CONDUCT.md), <b>especially</b> the last section (<i>Update 2022/03/26</i>) on the war in Ukraine and the limitations imposed on this tool: is a <b>personal</b> decision that I hope you understand. Otherwise, and if you don't want to contribute to this project because you don't agree with my decision, I will <b>deeply respect</b> it.

Enhancement & Issues
--------------------

Feel free to submit [bugs](https://github.com/rfc-st/humble/issues/new?assignees=&labels=&template=bug_report.md&title=), [feature requests](https://github.com/rfc-st/humble/issues/new?assignees=&labels=&template=feature_request.md&title=), [security vulnerabilities](https://github.com/rfc-st/humble/security/policy) and your suggestions to rafael.fcucalon@gmail.com.


Contributing
------------

* Please note, before sending a Pull Request, that <i>humble</i> is a multi-language tool (for now only English and Spanish are supported): take a look at [these](https://github.com/rfc-st/humble/tree/master/l10n) files, those ending in '_es.txt' are the Spanish translations. Therefore, each Pull Request that adds or modifies text strings must take into account both languages and update the corresponding files; also take a look at the functions <i>get_detail</i>, <i>get_l10n_content</i>, <i>print_detail</i>, <i>print_details</i>, <i>print_detail_l</i> and <i>print_detail_r</i>; they will help you understand how I handle literals and phrases.

* When contributing code, it must be <b>optimized</b>. My personal criterion is that every class, function, and method must achieve at least a <b>B</b> rank in [Radon's](https://radon.readthedocs.io/en/latest/commandline.html#the-cc-command) Cyclomatic Complexity analysis; otherwise review your changes and try to optimize and simplify them:
<p align="center">
<img src="https://github.com/rfc-st/humble/blob/master/screenshots/humble_radon.PNG" alt="Radon analysis shows no objects with a rank worse than 'B'." width=40% height=40%>
</p>

* Also make sure that the functions you add or modify achieve at least a <b>64%</b> Quality Score in [Sourcery's](https://docs.sourcery.ai/Coding-Assistant/Reference/Metrics/#quality-score) analysis; otherwise review your changes and try to optimize and simplify them:
<p align="center">
<img src="https://github.com/rfc-st/humble/blob/master/screenshots/humble_sourcery.PNG" alt="Sourcery analysis shows a Quality Score of 64%" width=40% height=40%>
</p>

* Finally, I have my <i>quirks</i> :), and I may not accept your Pull Request for certain reasons that I will <b>always</b> explain in the request itself. That, of course, doesn't mean that I don't value your interest, your time or your code: <b>always</b>, if I end up implementing your idea, I <b>will mention you</b> in the [Acknowledgements](https://github.com/rfc-st/humble/#acknowledgements) section.

Thank you for your time!.

Methodology
-----------

 0. Read the previous section! :)
 1. **Fork** the repo on GitHub
 2. **Clone** the project to your own machine
 3. **Commit** changes to your own branch
 4. **Push** your work back up to your fork
 5. Submit a **Pull request** so that I can review your changes

Copyright and Licensing
-----------------------

'humble' is licensed under the [MIT license](https://github.com/rfc-st/humble/blob/master/LICENSE).
