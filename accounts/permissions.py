from rest_framework import permissions



class UpdateOwnProfile(permissions.BasePermission):
    """Allow user to edit their own profile"""

    def has_object_permission(self, request, view, obj):
        """Check user is trying to edit their own profile"""

        if request.method in permissions.SAFE_METHODS:
            return True

        return obj.id == request.user.id



class UserProfilePermission(permissions.BasePermission):
    def has_permission(self, request, view):
        return request.user.is_authenticated




class MemberDetailPermission(permissions.BasePermission):
    def has_permission(self, request, view):
        username = view.kwargs.get('username')

        if request.method in permissions.SAFE_METHODS:
            return True

        if (request.user.is_authenticated and request.user.username == username) or (request.user.is_authenticated and request.user.is_superuser):
            return True

