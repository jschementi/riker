clean:
	-rm -Rf dist
	-rm -Rf build
	-rm -Rf riker.egg-info

.PHONY: clean

dist:
	python setup.py sdist

.PHONY: dist

upload:
	python setup.py sdist upload

.PHONY: upload
