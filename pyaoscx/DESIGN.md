# pyaoscx

## Overview

The pyaoscx (a.k.a. AOS-CX Python SDK) is a framework created to ease the access to
the Aruba switches running AOS-CX, using the REST API interface. The framework is
not intended to be a Network Management System (NMS). Instead, it is meant to
provide functions and classes to perform basic operations on the devices,
including the following:

1. Handling the session and remote connection.
1. Handling the allowed operations depending on their capabilities.
1. Handling the responses depending on the API version.
1. Basic data validation.
1. Raising meaningful errors.

And, also, if needed:

1. Caching data.
1. Handling notifications.

## Design drivers

pyaoscx uses the object-oriented approach. Instead of having separate modules to
perform specific operations, it connect several features together to represent
the operational state of the switch. Such pattern allows the client to keep track
of the switch configuration in its internal data structures.


Every single feature must be represented in a class. Such a class may or may not
be contained in another class or a collection. For example, the `Interface`
represents a specific Interface, and it may contain references to other `VLANs`, `VRFs`,
and depending on the use case, the `VSF` or `VSX` configuration. Also, an
`Interface` may be represented as a `LAG`, meaning that it may contain
references to more than a single physical port.

### pyaoscx Modules
Each pyaoscx module is defined as a Python Class,  in which it contains method 
definitions to generate and manage a module through  REST API call or multiple 
REST API calls. All module creation is managed through a flag attribute materialized. 
This attribute will be True if the module exists within the Switch Device, False otherwise. 
This will be updated whenever a POST or GET called is done.
 
Each pyaoscx Module has a list of important attributes besides materialized:
* session: use to make the HTTP requests, among other things.
* config_attrs: list of attributes writable to each specific object
* original_attributes: dictionary with object information and attributes right
    after performing a GET request. 
* modified: Flag to verify if object was modified, in case it was not the PUT 
    request is not made.

### Materialized objects

The attributes for a local object in the SDK may not match the current configuration on the switch.
Creating a local object in the SDK does not mean the object was created in the device.
The internal attributes can be filled with _artificial_ data, which cannot be
considered _materialized_ unless the object was retrieved from the device with
a __get__ operation, or the object was created with a __create__ operation.

### Operations

REST API allows a well-known list of HTTP verbs. They must be mapped to class-
specific operations to keep the same behavior along this SDK.

#### Get

This method maps to the HTTP GET verb. It allows to retrieve the data from the
device, converting the JSON response into the corresponding internal attributes
of the object. Object attributes must match 1:1 with the device information.

#### Create

This method maps to the HTTP POST verb. It retrieves a list of attributes from 
the object known as writable attributes, creating a body for the
POST request.

#### Update

This method maps to the HTTP PUT verb. Just as the CREATE, retrieves a list of
attributes from the object known as writable attributes. The difference
is the UPDATE methods makes a PUT Request. It's important to know that this method
is executed only if the object is materialized.

##### NOTIFICATIONS

#### Set

Given that the REST API does not provide support to the HTTP PATCH verb yet, all
the operations to change the device configuration must use the HTTP PUT verb.
It means that the the original attributes must be retrieved first, then change
the values required, and finally perform the change. This operation cannot be
performed on an unmaterialized object.


### Session management

In order to perform any operation in the device, a connection must be
established. The session is an object representing it. It keeps the credential
information, such as `username` and `password`, and, once established, it also
keeps the session cookie. There is an assumption that all the operations
performed should be done with the same REST API version. Therefore, the session
 also contains the version the client wants to use.

The session state must be validated every time an operation must be performed.
Therefore, using a Python decorator is the suggested approach.

However, in order to prevent using a _global accessible object_ representing
the session, and passing it as a parameter in every call, the SDK objects may
receive the session object as _mandatory parameter_ in the constructor.

### Factory Pattern

The REST API request and responses vary depending on the version. It means that
the internal structure of the payload changes, and the SDK must take care of it.
A Factory class is used to create new objects -- both python objects and modules
inside a switch AOS-CX Device.

If a module is created using the pyaoscx Factory, it's going to be set with the given
state in each creation method. 

## Main classes

### Session

The session class keeps the connection parameters. When a connection is established,
it also records the session cookie and the last time the connection was used, which
can help to identify whether the session is still valid because of the idle time.
The following fields will be required to store the main session information:

* Username
* Password
* Cookie
* API version
* Last operation timestamp

### API

Represents the API version used. Keeps all the important information
for the version and the methods related to it:

* release date
* version number
* default selector
* default depth


### Device

This class identifies the switch. It keeps all the basic internal parameters
which defines the device identity, like serial number and name, but, most importantly,
the device's capacities and capabilities. The latter parameters allow to decide
what kind of operations can be performed on a switch, given some features are
available on a certain family of devices.

* Name
* Serial
* Capacities
* Capabilities

### Configuration

This class represents a Device's configuration and all of its attributes. It's used to
configure the device, get full config structure, backup configuration, among other things.


### Error handling

Leveraging the Python infrastructure, the exceptions are the best
mechanism to handle the errors. An exception may report internal details
about the issue found, by returning error codes and descriptive error strings.

The following hierarchical organization will help classify the possible errors,
and, furthermore, let the SDK client know what exactly happened when calling
a function.

#### Exceptions

1. GenericOperationError
2. ResponseError
3. VerificationError
