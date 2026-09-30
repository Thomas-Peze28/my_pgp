NAME    =   my_pgp

ENTRY   =   src/main.py

all: $(NAME)

$(NAME):
	@cp $(ENTRY) $(NAME)
	@chmod +x $(NAME)

clean:
	rm -rf __pycache__ src/__pycache__

fclean: clean
	@rm -f $(NAME)

re: fclean all

.PHONY: all clean fclean re