# multi-user-blog
A simple (Medium-esque) multi-user blog made as I learn about the [Google App Engine](https://cloud.google.com/appengine/docs).

Project specifications from Udacity's [backend](https://www.udacity.com/course/intro-to-backend--ud171) course, and I've implemented some other features that occured to me. Share Bootstrap's free [Clean Blog](https://startbootstrap.com/template-overviews/clean-blog/) template was built upon to make a pretty front-end. Since I didn't always use the files as intended but instead based on how they looked (ex. contact me -> login/signup), class names in the templates aren't all properly descriptive. I think the MIT license requires that derivative/modified works also displays the license, so I've included it.

Features:
* Sign-in (with profiles that display posts and comments, total likes on comments and posts)
* Comment on posts (todo)
* Like posts/comments (but not your own)
* Edit your own posts

I know some things are done in silly ways (ex. rerendering page on like/unlike) but I'm making it up as I go :wink:. Google App Engine datastore probably isn't the best choice for this either.
