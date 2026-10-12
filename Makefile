NAME    =   my_pgp

ENTRY   =   src/main.py

all: $(NAME)

$(NAME): $(ENTRY)
	@cp $(ENTRY) $(NAME)
	@chmod +x $(NAME)

clean:
	@find . -type d -name "__pycache__" -exec rm -rf {} +
	@find . -type f -name "*.pyc" -delete

fclean: clean
	@rm -f $(NAME)

re: fclean all

tests_run:
	@python3 -m unittest discover -s tests -p "test_*.py" -v

.PHONY: all clean fclean re tests_run