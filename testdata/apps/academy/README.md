# Academy

Courses, enrollments, submissions and reviews. It is the third app in the Office demo (with Notebook and Falak.me).

| Entity | Who owns a row | Who else can read it |
|---|---|---|
| course | its teacher | everyone signed in, if published (title, description only) |
| enrollment | the student | the course's teacher (`related: course`) |
| submission | the student | the course's teacher (`related: course`) |
| review | the teacher who wrote it | the student who owns the submission (`related: submission`) |

Roles come from Office: a person is a `teacher` in this app, or has no role (a student).

**Limits.** A relationship rule cannot allow `create`, so nothing stops a teacher from reviewing a submission of someone else's course (the review would be unreachable to that student, but it exists). A command or custom check can close that gap later.

```
falak serve testdata/apps/academy
```
