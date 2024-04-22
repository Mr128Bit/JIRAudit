MAX_SCORE = 0
CURRENT_SCORE = 0


def update_score(score: int, max_score: int):
    global MAX_SCORE
    global CURRENT_SCORE

    MAX_SCORE += max_score
    CURRENT_SCORE += score


def print_score():
    print(
        f"\nYour jira instance reached a score of {CURRENT_SCORE}/\033[93m{MAX_SCORE}\033[00m\n"
    )
