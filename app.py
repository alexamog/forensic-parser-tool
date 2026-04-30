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

        match choice:
            case "1":
                print("\nLNK File Parser: reads shell link files from the current user's Recent Items folder.")
                from lnk_file_parser import main as run
                run()
            case "2":
                print("\nPrefetch Parser: reads prefetch files from C:\\Windows\\Prefetch to show program execution history.")
                from prefetch_parser import main as run
                run()
            case "3":
                print("\nRecycle Bin Parser: reads $I metadata files from C:\\$Recycle.Bin to show deleted file history.")
                from recycle_bin_parser import main as run
                run()
            case "4":
                print("\nShimcache parser coming soon.")
            case "5":
                print("\nAmcache parser coming soon.")
            case "6":
                print("\nTimeline Correlator: merges all parser results into a single chronological timeline.")
                from timeline_correlator import main as run
                run()
            case "0":
                print("\nExiting.")
                sys.exit(0)
            case _:
                print("\nInvalid choice. Please enter a number from the menu.")


if __name__ == "__main__":
    main()
