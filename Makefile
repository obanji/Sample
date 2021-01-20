run:
	# gcc -g subject/duktape/duktape.c -lm
	gcc -g subject/csv/csv.c
	#gcc -g subject/komplott/swizzle.c -ldl
	gdb --batch-silent -x ExecutionTree.py
clean:
	rm tree
	rm a.out
	rm gdb.txt