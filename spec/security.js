describe('security issues', function() {
    describe('GH-1495: Prevent Remote Code Execution via constructor', function() {
        // Note: In upstream Handlebars 4.x, constructor access is blocked at runtime,
        // allowing enumerable 'constructor' properties on data objects. In this 1.3.0
        // fork, constructor is blocked at parse time, so it is unconditionally denied.
        it('should not allow constructors to be accessed', function() {
            shouldThrow(function() {
                CompilerContext.compile('{{constructor.name}}');
            }, Error);
        });

        it('should not allow constructors to be accessed even with enumerable property', function() {
            shouldThrow(function() {
                CompilerContext.compile('{{constructor.name}}');
            }, Error);
        });
    });

    describe('GH-1595: dangerous properties', function() {
        var templates = [
            '{{__defineGetter__}}',
            '{{__defineSetter__}}',
            '{{__lookupGetter__}}',
            '{{__proto__}}',
        ];

        templates.forEach(function(template) {
            describe('access should be denied to ' + template, function() {
                it('by default', function() {
                    shouldThrow(function() {
                        CompilerContext.compile(template);
                    }, Error);
                });
            });
        });
    });
});
