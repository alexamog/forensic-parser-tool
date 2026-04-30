import sys


MENU = """
========================================
    Windows Forensic Parser Tools
========================================
 1. LNK File Parser
 2. Prefetch Parser         (requires admin)
 3. Recycle Bin Parser      (requires admin)
 4. Shimcache Parser        (coming soon)
 5. Amcache Parser          (coming soon)
----------------------------------------
 6. Build Timeline
----------------------------------------
 0. Exit
========================================
"""


def main():
    while True:
        print(MENU)
        choice = input("Select a parser: ").strip()

        if choice == "1":
            from lnk_file_parser import main as run
            run()
        elif choice == "2":
            from prefetch_parser import main as run
            run()
        elif choice == "3":
            from recycle_bin_parser import main as run
            run()
        elif choice == "4":
            print("\nShimcache parser coming soon.")
        elif choice == "5":
            print("\nAmcache parser coming soon.")
        elif choice == "6":
            from timeline_correlator import main as run
            run()
        elif choice == "0":
            print("\nExiting.")
            sys.exit(0)
        else:
            print("\nInvalid choice. Please enter a number from the menu.")


if __name__ == "__main__":
    main()
