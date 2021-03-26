install:
	pyinstaller -F scanner.py --add-data 'static/logo.png:static/' --add-data 'model/classifier.pkl:model/' --add-data 'model/features.pkl:model/' --hidden-import='sklearn' --hidden-import='sklearn.ensemble._forest' --hidden-import='sklearn.neighbors._typedefs' --hidden-import='sklearn.utils._weight_vector' --hidden-import='sklearn.neighbors._quad_tree' --hidden-import='PIL._tkinter_finder'
	cp -r model/ dist/model/
	cp -r static/ dist/static/
	pyinstaller -D scanner.spec
	rm -r __pycache__/
	rm -r build/
	rm scanner.spec
	ln -s dist/scanner scanner

clean:
	rm -r dist/
	rm scanner
