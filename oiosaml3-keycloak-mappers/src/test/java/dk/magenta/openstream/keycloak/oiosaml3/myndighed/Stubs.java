// SPDX-FileCopyrightText: 2026 Magenta ApS <info@magenta.dk>
// SPDX-License-Identifier: AGPL-3.0-only
package dk.magenta.openstream.keycloak.oiosaml3.myndighed;

import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import org.keycloak.models.GroupModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;

/**
 * Minimal stand-ins for the Keycloak model interfaces the mapper reads, built
 * with JDK proxies so the tests need neither a server nor a mocking library.
 * Any method the mapper is not expected to call throws, so a test fails
 * loudly if the mapper starts depending on more of the model.
 */
final class Stubs {

    private Stubs() {}

    /** A group with attributes; call {@link Group#child} to nest groups. */
    static final class Group {
        final String id;
        final Group parent;
        final Map<String, List<String>> attributes = new LinkedHashMap<>();
        final GroupModel model;

        private Group(String id, Group parent) {
            this.id = id;
            this.parent = parent;
            this.model = proxy(GroupModel.class, id, (method, args) -> switch (method.getName()) {
                case "getId", "getName" -> id;
                case "getParent" -> parent == null ? null : parent.model;
                case "getParentId" -> parent == null ? null : parent.id;
                case "getAttributeStream" -> attributes.getOrDefault((String) args[0], List.of()).stream();
                case "getFirstAttribute" -> {
                    List<String> values = attributes.getOrDefault((String) args[0], List.of());
                    yield values.isEmpty() ? null : values.get(0);
                }
                case "getAttributes" -> attributes;
                default -> unsupported(GroupModel.class, method);
            });
        }

        Group attr(String name, String... values) {
            attributes.put(name, Arrays.asList(values));
            return this;
        }

        Group child(String childId) {
            return new Group(childId, this);
        }
    }

    static Group group(String id) {
        return new Group(id, null);
    }

    static UserSessionModel session(String username, Group... groups) {
        UserModel user = proxy(UserModel.class, username, (method, args) -> switch (method.getName()) {
            case "getUsername" -> username;
            case "getGroupsStream" -> Stream.of(groups).map(g -> g.model);
            default -> unsupported(UserModel.class, method);
        });
        return proxy(UserSessionModel.class, "session:" + username, (method, args) -> switch (method.getName()) {
            case "getUser" -> user;
            default -> unsupported(UserSessionModel.class, method);
        });
    }

    /** A user with a name and attributes, for the NameID mapper. */
    static final class User {
        String id = "f3a1c2d4-0000-4000-8000-000000000001";
        String username;
        String firstName;
        String lastName;
        final Map<String, List<String>> attributes = new LinkedHashMap<>();
        int writes;
        boolean readOnly;

        private User(String username) {
            this.username = username;
        }

        User id(String value) {
            id = value;
            return this;
        }

        User name(String first, String last) {
            firstName = first;
            lastName = last;
            return this;
        }

        User attr(String name, String... values) {
            attributes.put(name, Arrays.asList(values));
            return this;
        }

        UserSessionModel session() {
            UserModel user = proxy(UserModel.class, username, (method, args) -> switch (method.getName()) {
                case "getId" -> id;
                case "getUsername" -> username;
                case "getFirstName" -> firstName;
                case "getLastName" -> lastName;
                case "getFirstAttribute" -> {
                    List<String> values = attributes.getOrDefault((String) args[0], List.of());
                    yield values.isEmpty() ? null : values.get(0);
                }
                case "setSingleAttribute" -> {
                    if (readOnly) {
                        throw new IllegalStateException("user is read-only");
                    }
                    writes++;
                    attributes.put((String) args[0], List.of((String) args[1]));
                    yield null;
                }
                default -> unsupported(UserModel.class, method);
            });
            return proxy(UserSessionModel.class, "session:" + username, (method, args) -> switch (method.getName()) {
                case "getUser" -> user;
                default -> unsupported(UserSessionModel.class, method);
            });
        }
    }

    static User user(String username) {
        return new User(username);
    }

    private interface Handler {
        Object handle(Method method, Object[] args);
    }

    private static <T> T proxy(Class<T> type, String label, Handler handler) {
        Object proxy = Proxy.newProxyInstance(
                Stubs.class.getClassLoader(),
                new Class<?>[] {type},
                (self, method, args) -> switch (method.getName()) {
                    case "toString" -> type.getSimpleName() + "(" + label + ")";
                    case "hashCode" -> System.identityHashCode(self);
                    case "equals" -> self == args[0];
                    default -> handler.handle(method, args);
                });
        return type.cast(proxy);
    }

    private static Object unsupported(Class<?> type, Method method) {
        throw new UnsupportedOperationException(
                type.getSimpleName() + "." + method.getName() + " is not stubbed");
    }
}
