 
# Stackify Heroku Buildpack

The Stackify Heroku Buildpack 
 
### Installation 

#### Add Stackify Buildpack 

```
heroku buildpacks:add -i=1 https://github.com/stackify/heroku-buildpack-stackify.git
```

#### Configure Buildpack 

```
heroku config:set STACKIFY_KEY="XXXXXXXXXX"
heroku config:set STACKIFY_APPLICATION_NAME="Ruby Application" 
heroku config:set STACKIFY_ENVIRONMENT_NAME="Production" 
```

 


