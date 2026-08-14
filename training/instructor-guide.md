# Instructor Guide

## What this course is for

Learners leave able to make and defend security decisions about an agentic AI system, operate its
controls, attack it in an authorized lab, read its evidence, and say precisely what a green build
does and does not establish.

They do not leave with an architecture to copy. The repository is a worked example whose most useful
parts are its refusals.

## Teaching stance

- **Do not answer for a control during a lab.** A learner told the answer has not tested it.
- **Let the traps spring.** Lab 1 Step 2 and Lab 3 Step 6 both depend on the learner being wrong
   first. Warning them removes the lesson.
- **Reward correct scepticism over correct answers.** A learner who contains every attack and then
   says "this proves less than it looks like" has understood the course.

## Grading calibration

| Signal | Read |
|---|---|
| Learner declares victory at corpus admission | Has not yet distinguished admission from effect. Redirect to Lab 2 Step 4 |
| Learner marks a control `implemented` to make a build pass | The exact failure the course exists to prevent. Discuss openly, do not penalise privately |
| Learner adds a red-team case that passes with the control disabled | A case that cannot fail proves nothing. Full marks require the negative check |
| Cohort finds no genuine weakness | The labs are too easy or the reset is dirty. Investigate before the next cohort |

## Known defects in the material

Nine of twelve modules have concepts and objectives but no worked lab, solution, or assessment. They
are outlined against real artifacts and must not be presented as complete. Writing a lab guide is
cheap; writing one whose exercise fails for the right reason is not.

No accessibility review of the course material has been performed, and no cohort has run it. The
first delivery is a pilot of the course, and should be described that way to learners.

## Claims

Completing this course does not make a learner, or any system they build, compliant, certified,
cleared, or ready for production use. Say so in the first session, because the repository says so on
every page and learners notice when the instructor is looser than the material.
