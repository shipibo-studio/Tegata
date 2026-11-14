// The `tegata` command, inside its signed bundle. Same code as the plain build; only the signature differs.
import Foundation
import TegataCommand

exit(TegataCommand.run(Array(CommandLine.arguments.dropFirst()), style: .detect()))
