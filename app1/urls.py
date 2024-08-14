from django.urls import path,include
from .import views
urlpatterns = [
    path('',views.homepage,name='homepage'),
    path('loginpage1',views.loginpage1,name='loginpage1'),
    path('logincreate',views.logincreate,name='logincreate'),
    path('forgotpassword',views.forgotpassword,name='forgotpassword'),
    path('validate_username/', views.validate_username, name='validate_username'),  # New URL for username validation
    path('workersignup/', views.workersignup, name='workersignup'),
    path('adminhome', views.adminhome, name='adminhome'),
    path('newdepartment',views.newdepartment,name='newdepartment'),
    path('notifications',views.notifications,name='notifications'),
    path('preferreddept',views.preferreddept,name='preferreddept'),
    path('preferreddept/allow/<int:worker_id>/',views.preferreddept_allow, name='preferreddept_allow'),
    path('preferreddept/clear/<int:worker_id>/',views.preferreddept_clear, name='preferreddept_clear'),
    path('viewworkers/',views.viewworkers, name='viewworkers'),
    path('viewworkers/<int:special_dept_worker_id>/',views.viewworkers, name='viewworkers_with_special_worker'),  # With special_dept_worker_id
    path('delete_worker/<int:user_id>',views.delete_worker, name='delete_worker'),
    path('viewusers/',views.viewusers, name='viewusers'),
    path('delete_user/<int:user_id>/', views.delete_user, name='delete_user'),
    path('approvedworkers/', views.approvedworkers, name='approvedworkers'),
    path('user-details/<int:worker_id>/', views.user_details, name='user_details'),
    path('worker/<int:worker_id>/', views.user_details, name='user_details'),
    path('approvedisapprove/',views.approvedisapprove,name='approvedisapprove'),
    path('approve_worker/<int:user_id>/', views.approve_worker, name='approve_worker'),
    path('disapprove_worker/<int:user_id>/', views.disapprove_worker, name='disapprove_worker'),
    path('viewimages/<int:usermember_id>/', views.viewimages, name='viewimages'),
    path('workerhome',views.workerhome,name='workerhome'),
    path('workernotifications',views.workernotifications,name='workernotifications'),
    path('workerreviews',views.workerreviews, name='workerreviews'),
    path('workerpassword',views.workerpassword,name='workerpassword'),
    path('workerpassword1',views.workerpassword1,name='workerpassword1'),
    path('workerprofile',views.workerprofile,name='workerprofile'),
    path('workerprofile1',views.workerprofile1,name='workerprofile1'),
    path('workeraccept',views.worker_accept,name='workeraccept'),
    path('workeraccept/confirm/<int:request_id>/',views.confirm_request, name='confirm_request'),
    path('workeraccept/delete/<int:request_id>/',views.delete_request, name='delete_request'),
    path('toggle_completion/<int:request_id>/', views.toggle_completion, name='toggle_completion'),
    path('usersignup',views.usersignup,name='usersignup'),
    path('userreg1',views.userreg1,name='userreg1'),
    path('userhome',views.userhome,name='userhome'),
    path('userrequest',views.userrequest,name='userrequest'),
    path('supporting_image/<int:worker_id>/',views.supporting_image, name='supporting_image'),
    path('requestform', views.requestform, name='requestform'),
    path('userabout',views.userabout,name='userabout'),
    path('useraccount',views.useraccount,name='useraccount'),
    path('userprofile',views.userprofile,name='userprofile'),
    path('userprofile1',views.userprofile1,name='userprofile1'),
    path('userpassword',views.userpassword,name='userpassword'),
    path('userpassword1',views.userpassword1,name='userpassword1'),
    path('userreviews/<int:worker_id>/', views.userreviews, name='userreviews'),
    path('logout1',views.logout1,name='logout1'),
 

]

